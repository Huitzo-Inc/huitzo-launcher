use crate::dirs;
use crate::errors::Error;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;

/// GitHub Releases API URL for CLI distribution (hosted on the public launcher repo).
/// CLI releases are tagged `cli-v*` to distinguish from launcher releases (`v*`).
const CLI_RELEASES_URL: &str = "https://api.github.com/repos/Huitzo-Inc/huitzo-launcher/releases";

/// Information about a CLI release, parsed from cli-release.json.
#[derive(Debug)]
pub struct CliRelease {
    pub version: String,
    #[allow(dead_code)] // Reserved for future version-gating of launcher updates
    pub min_launcher_version: String,
    pub wheels: Vec<WheelInfo>,
}

/// A platform-specific wheel in a release.
#[derive(Debug)]
pub struct WheelInfo {
    pub platform_key: String,
    pub filename: String,
    pub sha256: String,
}

/// Returns the base platform key for the current OS/architecture.
///
/// Must match the prefix used in cli-release.json:
/// linux-x86_64, linux-aarch64, macos-x86_64, macos-arm64, windows-x86_64
pub fn current_platform() -> &'static str {
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "linux-x86_64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "linux-aarch64"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "macos-x86_64"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "macos-arm64"
    } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        "windows-x86_64"
    } else {
        "linux-x86_64" // fallback
    }
}

/// Fetch the latest CLI release manifest (cli-release.json) from GitHub Releases.
///
/// If `HUITZO_RELEASE_URL` is set, uses that as the base URL instead.
pub fn fetch_cli_release() -> Result<CliRelease, Error> {
    let releases_url =
        std::env::var("HUITZO_RELEASE_URL").unwrap_or_else(|_| CLI_RELEASES_URL.to_string());

    // Fetch latest release JSON
    let mut response = ureq::get(&releases_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("Failed to fetch CLI release: {e}")))?;

    let body_str = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Network(format!("Failed to read release response: {e}")))?;

    let releases: serde_json::Value = serde_json::from_str(&body_str)
        .map_err(|e| Error::Network(format!("Failed to parse releases JSON: {e}")))?;

    // Find the latest CLI release (tagged cli-v*)
    let release = releases
        .as_array()
        .ok_or_else(|| Error::Network("No releases found".to_string()))?
        .iter()
        .find(|r| {
            r["tag_name"]
                .as_str()
                .is_some_and(|t| t.starts_with("cli-v"))
        })
        .ok_or_else(|| Error::Network("No CLI release found (expected cli-v* tag)".to_string()))?;

    // Find cli-release.json asset
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::Network("No assets in CLI release".to_string()))?;

    let manifest_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some("cli-release.json"))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| {
            Error::Network("cli-release.json not found in release assets".to_string())
        })?;

    // Download and parse cli-release.json
    let mut manifest_response = ureq::get(manifest_url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("Failed to download cli-release.json: {e}")))?;

    let manifest_str = manifest_response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Network(format!("Failed to read cli-release.json: {e}")))?;

    let manifest: serde_json::Value = serde_json::from_str(&manifest_str)
        .map_err(|e| Error::Network(format!("Failed to parse cli-release.json: {e}")))?;

    // Parse into CliRelease struct
    let version = manifest["version"]
        .as_str()
        .ok_or_else(|| Error::Network("No version in cli-release.json".to_string()))?
        .to_string();

    let min_launcher_version = manifest["min_launcher_version"]
        .as_str()
        .unwrap_or("0.1.0")
        .to_string();

    let wheels_obj = manifest["wheels"]
        .as_object()
        .ok_or_else(|| Error::Network("No wheels in cli-release.json".to_string()))?;

    let mut wheels = Vec::new();
    for (key, val) in wheels_obj {
        let filename = val["filename"].as_str().unwrap_or("").to_string();
        let sha256 = val["sha256"].as_str().unwrap_or("").to_string();
        wheels.push(WheelInfo {
            platform_key: key.clone(),
            filename,
            sha256,
        });
    }

    Ok(CliRelease {
        version,
        min_launcher_version,
        wheels,
    })
}

/// Returns true if a compiled wheel exists for the given Python version on the current platform.
///
/// Used during Python selection in bootstrap to prefer interpreters that have a compiled wheel.
pub fn has_wheel_for(release: &CliRelease, python_version: (u8, u8)) -> bool {
    find_platform_wheel(release, Some(python_version)).is_ok()
}

/// Find the best matching wheel for the current platform and Python version.
///
/// Lookup order:
/// 1. `{platform}-cp{major}{minor}` — exact interpreter ABI match (e.g. `macos-arm64-cp313`)
/// 2. `{platform}` — version-agnostic fallback for older manifests or universal wheels
///
/// Pass `python_version` as `Some((major, minor))` when the interpreter version is known.
/// Pass `None` only as a last resort.
pub fn find_platform_wheel<'a>(
    release: &'a CliRelease,
    python_version: Option<(u8, u8)>,
) -> Result<&'a WheelInfo, Error> {
    let platform = current_platform();

    // 1. Try Python-version-specific key (e.g. "macos-arm64-cp313")
    if let Some((major, minor)) = python_version {
        let abi_key = format!("{platform}-cp{major}{minor}");
        if let Some(wheel) = release.wheels.iter().find(|w| w.platform_key == abi_key) {
            return Ok(wheel);
        }
    }

    // 2. Fall back to platform-only key for backwards compatibility
    release
        .wheels
        .iter()
        .find(|w| w.platform_key == platform)
        .ok_or_else(|| {
            Error::PipInstall(format!(
                "No compiled wheel for platform '{platform}' (python {:?}). Available: {}",
                python_version,
                release
                    .wheels
                    .iter()
                    .map(|w| w.platform_key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// Download a wheel file from a GitHub Release, verify its SHA-256 checksum,
/// and save it to the cache directory.
///
/// The wheel URL is constructed from the release tag and filename.
pub fn download_wheel(release_version: &str, wheel: &WheelInfo) -> Result<PathBuf, Error> {
    let cache_dir = dirs::huitzo_home().join("cache");
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| Error::PipInstall(format!("Failed to create cache dir: {e}")))?;

    let dest = cache_dir.join(&wheel.filename);

    // Construct download URL from the GitHub release (hosted on public launcher repo)
    let url = format!(
        "https://github.com/Huitzo-Inc/huitzo-launcher/releases/download/cli-v{}/{}",
        release_version, wheel.filename
    );

    // Allow override for testing
    let url = if let Ok(base) = std::env::var("HUITZO_RELEASE_DOWNLOAD_URL") {
        format!("{}/{}", base.trim_end_matches('/'), wheel.filename)
    } else {
        url
    };

    eprintln!("  Downloading {}...", wheel.filename);

    let mut response = ureq::get(&url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("Failed to download wheel: {e}")))?;

    let mut file = std::fs::File::create(&dest)
        .map_err(|e| Error::PipInstall(format!("Failed to create wheel file: {e}")))?;

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
            .map_err(|e| Error::PipInstall(format!("Failed to write wheel: {e}")))?;
    }

    // Verify checksum
    let computed = format!("{:x}", hasher.finalize());
    if computed != wheel.sha256 {
        let _ = std::fs::remove_file(&dest);
        return Err(Error::PipInstall(format!(
            "Wheel checksum mismatch!\n  Expected: {}\n  Got:      {}",
            wheel.sha256, computed
        )));
    }

    eprintln!("  Checksum verified.");
    Ok(dest)
}

/// Get the latest CLI version from GitHub Releases without downloading the wheel.
///
/// Used by the background update checker.
pub fn check_cli_release_version() -> Option<String> {
    let release = fetch_cli_release().ok()?;
    Some(release.version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_release(keys: &[&str]) -> CliRelease {
        CliRelease {
            version: "0.2.3".to_string(),
            min_launcher_version: "0.1.0".to_string(),
            wheels: keys
                .iter()
                .map(|k| WheelInfo {
                    platform_key: k.to_string(),
                    filename: format!("huitzo-0.2.3-{k}.whl"),
                    sha256: "abc".to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn current_platform_returns_valid_key() {
        let platform = current_platform();
        let valid = [
            "linux-x86_64",
            "linux-aarch64",
            "macos-x86_64",
            "macos-arm64",
            "windows-x86_64",
        ];
        assert!(
            valid.contains(&platform),
            "Unknown platform key: {platform}"
        );
    }

    #[test]
    fn find_platform_wheel_prefers_abi_key() {
        let platform = current_platform();
        let abi_key = format!("{platform}-cp313");
        let release = make_release(&[&abi_key, platform]);

        let wheel = find_platform_wheel(&release, Some((3, 13))).unwrap();
        assert_eq!(wheel.platform_key, abi_key, "Should prefer ABI-specific key");
    }

    #[test]
    fn find_platform_wheel_falls_back_to_platform_key() {
        let platform = current_platform();
        let release = make_release(&[platform]);

        let wheel = find_platform_wheel(&release, Some((3, 13))).unwrap();
        assert_eq!(wheel.platform_key, platform);
    }

    #[test]
    fn find_platform_wheel_abi_only_manifest() {
        let platform = current_platform();
        let abi_key = format!("{platform}-cp311");
        let release = make_release(&[&abi_key]);

        let wheel = find_platform_wheel(&release, Some((3, 11))).unwrap();
        assert_eq!(wheel.platform_key, abi_key);
    }

    #[test]
    fn find_platform_wheel_abi_mismatch_falls_back() {
        let platform = current_platform();
        let abi_key = format!("{platform}-cp311");
        let release = make_release(&[&abi_key, platform]);

        let wheel = find_platform_wheel(&release, Some((3, 13))).unwrap();
        assert_eq!(wheel.platform_key, platform, "cp313 miss → fall back to base key");
    }

    #[test]
    fn find_platform_wheel_no_python_version_uses_platform_key() {
        let platform = current_platform();
        let release = make_release(&[platform]);

        let wheel = find_platform_wheel(&release, None).unwrap();
        assert_eq!(wheel.platform_key, platform);
    }

    #[test]
    fn find_platform_wheel_returns_error_when_no_match() {
        let release = make_release(&["linux-x86_64-cp310"]);
        let platform = current_platform();
        let abi_key = format!("{platform}-cp310");
        if release
            .wheels
            .iter()
            .all(|w| w.platform_key != platform && w.platform_key != abi_key)
        {
            assert!(find_platform_wheel(&release, Some((3, 13))).is_err());
        }
    }
}
