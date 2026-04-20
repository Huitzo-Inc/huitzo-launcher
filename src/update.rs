use crate::dirs;
use crate::download;
use crate::errors::Error;
use crate::manifest::{self, PendingUpdate};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Check if update checking is disabled via environment variable.
pub fn should_skip() -> bool {
    std::env::var("HUITZO_SKIP_UPDATE_CHECK")
        .is_ok_and(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
}

/// Run the update check synchronously with a 5-second timeout.
///
/// Spawns the check in a thread so the network call is bounded; the main thread
/// blocks until the check completes or the timeout elapses, then proceeds to
/// `exec_into_python`. This guarantees the manifest is written before `execvp`
/// replaces the process (killing any detached thread).
pub fn sync_check() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        background_check();
        let _ = tx.send(());
    });
    // Proceed silently if the network is unreachable or slow.
    let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
}

/// Update check: queries GitHub Releases for newer launcher and CLI versions.
///
/// Checks the launcher first (higher priority), then the CLI.
/// Updates the manifest with the check timestamp and any pending update.
/// Errors are silently ignored.
pub fn background_check() {
    let Some(mut m) = manifest::load() else {
        return;
    };

    // Check for launcher self-update first (higher priority)
    if let Some(latest) = check_launcher_version() {
        m.pending_update = Some(PendingUpdate {
            kind: "launcher".to_string(),
            version: latest,
        });
    } else if let Some(latest) = download::check_cli_release_version() {
        // Only check CLI if launcher is already up-to-date
        if version_is_newer(&latest, &m.huitzo_version) {
            m.pending_update = Some(PendingUpdate {
                kind: "wheel".to_string(),
                version: latest,
            });
        }
    }

    m.last_update_check = manifest::now_secs();
    let _ = manifest::save(&m);
}

/// Check if a newer launcher version is available on GitHub Releases.
///
/// Queries all releases and filters for launcher tags (`v*`, excluding `cli-v*`).
/// Returns `Some(version)` if a newer version is available, `None` otherwise.
fn check_launcher_version() -> Option<String> {
    let releases = fetch_all_releases().ok()?;
    let latest = find_latest_launcher_version(&releases)?;
    let current = env!("CARGO_PKG_VERSION");
    if version_is_newer(&latest, current) {
        Some(latest)
    } else {
        None
    }
}

/// Fetch all releases from GitHub Releases API.
fn fetch_all_releases() -> Result<serde_json::Value, Error> {
    let url = "https://api.github.com/repos/Huitzo-Inc/huitzo-launcher/releases";
    let mut response = ureq::get(url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("GitHub API request failed: {e}")))?;

    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Network(format!("Failed to read GitHub response: {e}")))?;

    serde_json::from_str(&body)
        .map_err(|e| Error::SelfUpdate(format!("Failed to parse releases JSON: {e}")))
}

/// Extract the latest launcher version from a releases JSON array.
///
/// Launcher releases are tagged `v*` (e.g. `v0.2.3`).
/// CLI releases are tagged `cli-v*` and are excluded.
///
/// GitHub's Releases API returns releases in reverse chronological order,
/// so the first matching `v*` tag is the most recent launcher release.
fn find_latest_launcher_version(releases: &serde_json::Value) -> Option<String> {
    let tag = releases
        .as_array()?
        .iter()
        .filter_map(|r| r["tag_name"].as_str())
        .find(|t| t.starts_with('v') && !t.starts_with("cli-v"))?;

    // strip_prefix is guaranteed to succeed here (filter ensures 'v' prefix),
    // but unwrap_or is kept as defensive fallback.
    Some(tag.strip_prefix('v').unwrap_or(tag).to_string())
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
/// Filters the releases list for `v*` tags (excludes `cli-v*`) so that a CLI
/// release published after the latest launcher release does not shadow it.
/// Verifies integrity and atomically replaces the current binary.
pub fn self_update() -> Result<(), Error> {
    let current_version = env!("CARGO_PKG_VERSION");
    eprintln!("Checking for launcher updates (current: v{current_version})...");

    // 1. Fetch all releases and find the latest launcher release (v*, excluding cli-v*)
    let releases = fetch_all_releases()?;
    let release = find_latest_launcher_release(&releases)
        .ok_or_else(|| Error::SelfUpdate("No launcher release found (expected v* tag)".to_string()))?;

    let tag = release["tag_name"]
        .as_str()
        .ok_or_else(|| Error::SelfUpdate("No tag_name in release".to_string()))?;

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

/// Find the full release JSON object for the latest launcher release.
///
/// Launcher releases are tagged `v*` (e.g. `v0.2.5`); CLI releases are tagged
/// `cli-v*` and are excluded. Returns a reference into `releases`.
fn find_latest_launcher_release(releases: &serde_json::Value) -> Option<&serde_json::Value> {
    releases.as_array()?.iter().find(|r| {
        r["tag_name"]
            .as_str()
            .is_some_and(|t| t.starts_with('v') && !t.starts_with("cli-v"))
    })
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

    #[test]
    fn find_latest_launcher_version_picks_v_tag() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.3.0"},
                {"tag_name": "v0.2.5"},
                {"tag_name": "v0.2.4"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("0.2.5")
        );
    }

    #[test]
    fn find_latest_launcher_version_skips_cli_tags() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.5.0"},
                {"tag_name": "cli-v0.4.0"}
            ]"#,
        )
        .unwrap();
        assert_eq!(find_latest_launcher_version(&releases), None);
    }

    #[test]
    fn find_latest_launcher_version_empty_releases() {
        let releases: serde_json::Value = serde_json::from_str("[]").unwrap();
        assert_eq!(find_latest_launcher_version(&releases), None);
    }

    #[test]
    fn find_latest_launcher_version_no_v_prefix() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "0.2.5"}]"#).unwrap();
        assert_eq!(find_latest_launcher_version(&releases), None);
    }

    #[test]
    fn find_latest_launcher_release_skips_cli_tag_returns_full_object() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.3.0", "assets": []},
                {"tag_name": "v0.2.5",     "assets": [{"name": "huitzo-x86_64-apple-darwin"}]}
            ]"#,
        )
        .unwrap();
        let release = find_latest_launcher_release(&releases).unwrap();
        assert_eq!(release["tag_name"].as_str(), Some("v0.2.5"));
        assert!(release["assets"].as_array().is_some());
    }

    #[test]
    fn find_latest_launcher_release_returns_none_when_only_cli_tags() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[{"tag_name": "cli-v0.5.0"}, {"tag_name": "cli-v0.4.0"}]"#,
        )
        .unwrap();
        assert!(find_latest_launcher_release(&releases).is_none());
    }
}
