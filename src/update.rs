use crate::dirs;
use crate::download;
use crate::errors::Error;
use crate::manifest::{self, PendingUpdate};
use sha2::{Digest, Sha256};
use std::io::Read;

/// GitHub Releases API URL for the launcher.
const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/Huitzo-Inc/huitzo-launcher/releases/latest";

/// Check if update checking is disabled via environment variable.
pub fn should_skip() -> bool {
    std::env::var("HUITZO_SKIP_UPDATE_CHECK")
        .is_ok_and(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
}

/// Background update check: queries GitHub Releases for a newer CLI version.
///
/// Updates the manifest with the check timestamp and any pending update.
/// Errors are silently ignored (non-blocking).
pub fn background_check() {
    let Some(mut m) = manifest::load() else {
        return;
    };

    // Check GitHub Releases for newer compiled CLI wheel
    if let Some(latest) = download::check_cli_release_version() {
        if version_is_newer(&latest, &m.huitzo_version) {
            eprintln!(
                "huitzo {latest} is available (installed: {}). \
                 Update will apply on next launch.",
                m.huitzo_version
            );
            m.pending_update = Some(PendingUpdate {
                kind: "wheel".to_string(),
                version: latest,
            });
        }
    }

    m.last_update_check = manifest::now_secs();
    let _ = manifest::save(&m);
}

/// Returns the platform-specific asset name for the current target triple.
pub fn platform_asset_name() -> &'static str {
    if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        "huitzo-x86_64-pc-windows-msvc.exe"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "huitzo-aarch64-apple-darwin"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "huitzo-x86_64-apple-darwin"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "huitzo-aarch64-unknown-linux-musl"
    } else {
        // Default to Linux x86_64
        "huitzo-x86_64-unknown-linux-musl"
    }
}

/// Self-update the launcher binary from GitHub Releases.
///
/// Checks the latest release, downloads the binary and checksum,
/// verifies integrity, and atomically replaces the current binary.
pub fn self_update() -> Result<(), Error> {
    let current_version = env!("CARGO_PKG_VERSION");
    eprintln!("Checking for launcher updates (current: v{current_version})...");

    // 1. Fetch latest release metadata from GitHub
    let release = fetch_latest_release()?;
    let tag = release["tag_name"]
        .as_str()
        .ok_or_else(|| Error::SelfUpdate("No tag_name in release response".to_string()))?;

    // Strip leading 'v' if present for version comparison
    let latest_version = tag.strip_prefix('v').unwrap_or(tag);

    // 2. Compare versions
    if !version_is_newer(latest_version, current_version) {
        eprintln!("Launcher is up to date (v{current_version}).");
        return Ok(());
    }

    eprintln!("New launcher version available: v{latest_version}");

    // 3. Find the asset for the current platform
    let asset_name = platform_asset_name();
    let checksum_name = format!("{asset_name}.sha256");

    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::SelfUpdate("No assets in release".to_string()))?;

    let binary_url = find_asset_url(assets, asset_name)?;
    let checksum_url = find_asset_url(assets, &checksum_name)?;

    // 4. Set up temp directory
    let tmp_dir = dirs::huitzo_home().join("tmp");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| Error::SelfUpdate(format!("Failed to create tmp dir: {e}")))?;

    let tmp_binary = tmp_dir.join("huitzo-new");

    // 5. Download checksum file
    eprintln!("  Downloading checksum...");
    let expected_hash = download_checksum(&checksum_url)?;

    // 6. Download binary and compute SHA-256 incrementally
    eprintln!("  Downloading {asset_name}...");
    let computed_hash = download_and_hash(&binary_url, &tmp_binary)?;

    // 7. Verify checksum
    if computed_hash != expected_hash {
        // Clean up the bad download
        let _ = std::fs::remove_file(&tmp_binary);
        return Err(Error::SelfUpdate(format!(
            "Checksum mismatch!\n  Expected: {expected_hash}\n  Got:      {computed_hash}"
        )));
    }
    eprintln!("  Checksum verified.");

    // 8. Make the new binary executable (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_binary, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| Error::SelfUpdate(format!("Failed to set permissions: {e}")))?;
    }

    // 9. Atomically replace the current binary
    let current_exe = std::env::current_exe()
        .map_err(|e| Error::SelfUpdate(format!("Cannot determine current executable: {e}")))?;

    eprintln!("  Replacing {}...", current_exe.display());
    std::fs::rename(&tmp_binary, &current_exe)
        .map_err(|e| Error::SelfUpdate(format!("Failed to replace binary: {e}")))?;

    eprintln!("Launcher updated to v{latest_version} successfully.");
    Ok(())
}

/// Fetch the latest release JSON from GitHub Releases API.
fn fetch_latest_release() -> Result<serde_json::Value, Error> {
    let mut response = ureq::get(GITHUB_RELEASES_URL)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("GitHub API request failed: {e}")))?;

    let body_str = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Network(format!("Failed to read GitHub response: {e}")))?;

    serde_json::from_str(&body_str)
        .map_err(|e| Error::SelfUpdate(format!("Failed to parse release JSON: {e}")))
}

/// Find the download URL for a named asset in the release assets array.
fn find_asset_url(assets: &[serde_json::Value], name: &str) -> Result<String, Error> {
    for asset in assets {
        if asset["name"].as_str() == Some(name) {
            return asset["browser_download_url"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| Error::SelfUpdate(format!("Asset '{name}' has no download URL")));
        }
    }
    Err(Error::SelfUpdate(format!(
        "No asset named '{name}' in release. Available: {}",
        assets
            .iter()
            .filter_map(|a| a["name"].as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// Download the checksum file and extract the hex hash.
///
/// Expected format: `<hex_hash>  <filename>\n` or just `<hex_hash>\n`
fn download_checksum(url: &str) -> Result<String, Error> {
    let mut response = ureq::get(url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("Failed to download checksum: {e}")))?;

    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Network(format!("Failed to read checksum: {e}")))?;

    // Parse: either "hash  filename" or just "hash"
    let hash = body
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::SelfUpdate("Empty checksum file".to_string()))?;

    // Validate it looks like a SHA-256 hex string
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::SelfUpdate(format!(
            "Invalid checksum format: '{hash}'"
        )));
    }

    Ok(hash.to_lowercase())
}

/// Download a binary to `dest`, computing SHA-256 incrementally.
///
/// Returns the hex-encoded hash of the downloaded file.
fn download_and_hash(url: &str, dest: &std::path::Path) -> Result<String, Error> {
    let mut response = ureq::get(url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("Failed to download binary: {e}")))?;

    let mut file = std::fs::File::create(dest)
        .map_err(|e| Error::SelfUpdate(format!("Failed to create temp file: {e}")))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut reader = response.body_mut().as_reader();

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error::Network(format!("Download interrupted: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| Error::SelfUpdate(format!("Failed to write binary: {e}")))?;
    }

    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}

/// Simple version comparison: "0.2.0" > "0.1.7".
///
/// Compares numeric segments left-to-right.
fn version_is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse().ok()).collect() };
    let l = parse(latest);
    let c = parse(current);
    l > c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(version_is_newer("0.2.0", "0.1.7"));
        assert!(version_is_newer("1.0.0", "0.99.99"));
        assert!(!version_is_newer("0.1.7", "0.1.7"));
        assert!(!version_is_newer("0.1.6", "0.1.7"));
    }

    #[test]
    fn version_comparison_edge_cases() {
        // Single segment
        assert!(version_is_newer("2", "1"));
        assert!(!version_is_newer("1", "2"));
        // Different lengths
        assert!(version_is_newer("0.1.1", "0.1"));
        assert!(!version_is_newer("0.1", "0.1.1"));
        // v-prefix stripped before calling
        assert!(version_is_newer("0.2.0", "0.1.0"));
    }

    #[test]
    fn platform_asset_name_returns_valid_name() {
        let name = platform_asset_name();
        assert!(
            name.starts_with("huitzo-"),
            "Expected 'huitzo-' prefix, got: {name}"
        );
        // Should contain a known target triple fragment
        let valid_fragments = [
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ];
        assert!(
            valid_fragments.iter().any(|f| name.contains(f)),
            "Unexpected platform asset name: {name}"
        );
    }
}
