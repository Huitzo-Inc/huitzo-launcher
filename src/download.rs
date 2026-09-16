// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use crate::dirs;
use crate::errors::{Error, FeedError};
use crate::update::select_newest_release;
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
///
/// `macos-x86_64` is a key no release will ever carry (D2 — Intel macOS is
/// unsupported). It is still produced here so the miss is reported honestly by
/// [`find_platform_wheel`] rather than silently mapped onto the arm64 build.
/// **T5 seam:** the explicit "Apple Silicon required" refusal belongs upstream
/// of this — before a venv is built — and is T5's to add; this function and
/// `Error::NoWheel` are the fallback, not that refusal.
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

/// How long the launcher will wait on the release feed before calling it
/// unreachable. Without a bound, a blackholed connection hangs `huitzo` forever
/// instead of producing the error this module exists to produce.
const FEED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A GitHub token to raise the 60-req/hour unauthenticated allowance, if the
/// environment offers one AND the feed is actually GitHub.
///
/// The host check is not cosmetic: `HUITZO_RELEASE_URL` can point anywhere, and
/// attaching the user's token to an arbitrary host would hand it to whoever set
/// that variable.
fn github_token_for(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
    if host != "api.github.com" {
        return None;
    }
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
}

/// GET `url` and return its body, classifying every failure as a [`FeedError`].
///
/// The classification is the point (M11): "GitHub is rate-limiting this IP",
/// "there is no network" and "that URL served something else" are three
/// different problems with three different remedies, and the old code turned
/// all of them into `Option::None` and then into a silent PyPI stub install.
fn fetch_feed(url: &str) -> Result<String, Error> {
    let unavailable = |cause: FeedError| Error::FeedUnavailable {
        url: url.to_string(),
        cause,
    };

    let mut request = ureq::get(url)
        .config()
        .http_status_as_error(false) // we classify the status ourselves
        .timeout_global(Some(FEED_TIMEOUT))
        .build()
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "huitzo-launcher");
    if let Some(token) = github_token_for(url) {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    let mut response = request
        .call()
        .map_err(|e| unavailable(FeedError::Unreachable(e.to_string())))?;

    let status = response.status().as_u16();
    if status != 200 {
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        return Err(unavailable(if status == 403 || status == 429 {
            FeedError::Forbidden {
                status,
                remaining: header("x-ratelimit-remaining").and_then(|v| v.parse().ok()),
                retry_after: header("x-ratelimit-reset")
                    .and_then(|v| v.parse().ok())
                    .and_then(describe_reset),
            }
        } else {
            FeedError::Status(status)
        }));
    }

    response
        .body_mut()
        .read_to_string()
        .map_err(|e| unavailable(FeedError::Unreachable(format!("truncated response: {e}"))))
}

/// Render GitHub's `x-ratelimit-reset` (a Unix timestamp) as a wait the user
/// can act on. `None` when the clock says the reset is already behind us —
/// "resets in 0 minutes" would be noise, not information.
fn describe_reset(reset_epoch: u64) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let seconds = reset_epoch.checked_sub(now)?;
    Some(match seconds {
        0 => return None,
        1..=90 => format!("in {seconds}s"),
        _ => format!("in {}min", seconds.div_ceil(60)),
    })
}

/// Fetch the latest CLI release manifest (cli-release.json) from GitHub Releases.
///
/// If `HUITZO_RELEASE_URL` is set, uses that as the base URL instead.
///
/// Every failure is an [`Error::FeedUnavailable`] naming which kind it was; a
/// caller that cannot read the feed has no wheel to install and no business
/// guessing (D5).
pub fn fetch_cli_release() -> Result<CliRelease, Error> {
    let releases_url =
        std::env::var("HUITZO_RELEASE_URL").unwrap_or_else(|_| CLI_RELEASES_URL.to_string());

    let malformed = |detail: String| Error::FeedUnavailable {
        url: releases_url.clone(),
        cause: FeedError::Malformed(detail),
    };

    let body_str = fetch_feed(&releases_url)?;

    let releases: serde_json::Value = serde_json::from_str(&body_str)
        .map_err(|e| malformed(format!("release list is not JSON: {e}")))?;

    if !releases.is_array() {
        return Err(malformed("release list is not a JSON array".to_string()));
    }

    // Find the latest CLI release (tagged cli-v*) by version, not by position:
    // every cli-v* release shares one `created_at`, so the API's order among
    // them is arbitrary (#48).
    let release = find_latest_cli_release(&releases)
        .ok_or_else(|| malformed("no cli-v* release in the release list".to_string()))?;

    // Find cli-release.json asset
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| malformed("newest cli-v* release lists no assets".to_string()))?;

    let manifest_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some("cli-release.json"))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| malformed("cli-release.json is not among the release assets".to_string()))?;

    // Download and parse cli-release.json
    let manifest_str = fetch_feed(manifest_url)?;

    let manifest: serde_json::Value = serde_json::from_str(&manifest_str)
        .map_err(|e| malformed(format!("cli-release.json is not JSON: {e}")))?;

    parse_manifest(&manifest).map_err(malformed)
}

/// Turn a parsed `cli-release.json` body into a [`CliRelease`].
///
/// Split out from the fetch so the shape contract is testable without a server.
fn parse_manifest(manifest: &serde_json::Value) -> Result<CliRelease, String> {
    let version = manifest["version"]
        .as_str()
        .ok_or("cli-release.json has no `version`")?
        .to_string();

    // Parsed, deliberately not enforced here: gating the launcher on
    // `min_launcher_version` is T3's. It is carried so that error paths can
    // quote the release they came from, and so T3 has it without a re-fetch.
    let min_launcher_version = manifest["min_launcher_version"]
        .as_str()
        .unwrap_or("0.1.0")
        .to_string();

    let wheels_obj = manifest["wheels"]
        .as_object()
        .ok_or("cli-release.json has no `wheels` object")?;

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
/// This allows cli-release.json to carry wheels for multiple Python versions
/// while remaining backwards compatible with launchers that only emit
/// platform-only keys.
///
/// Pass `python_version` as `Some((major, minor))` when the interpreter version is known.
/// Pass `None` only as a last resort.
pub fn find_platform_wheel(
    release: &CliRelease,
    python_version: Option<(u8, u8)>,
) -> Result<&WheelInfo, Error> {
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
            let mut available: Vec<String> = release
                .wheels
                .iter()
                .map(|w| w.platform_key.clone())
                .collect();
            // Map order is arbitrary; the user is reading this list to compare
            // it against their own platform, so sort it.
            available.sort();
            Error::NoWheel {
                platform: platform.to_string(),
                // `None` only reaches here from `has_wheel_for`-style probes,
                // which discard the error. The message always names a real
                // interpreter on the install path.
                python_version: python_version.unwrap_or((0, 0)),
                feed_version: release.version.clone(),
                available,
            }
        })
}

/// Stream the response body of `url` to `dest`, computing SHA-256 on the way,
/// and verify it matches `expected_sha256` (hex, lowercase).
///
/// On mismatch the file is deleted and a `BundleVerify` error is returned so
/// callers downstream of the launcher's trust boundary can distinguish a
/// checksum failure from a generic network failure. Use this for any
/// signature-anchored artefact (capability bundles, wheels). `dest`'s parent
/// directory is created if missing.
pub fn stream_to_file_with_hash(
    url: &str,
    dest: &std::path::Path,
    expected_sha256: &str,
) -> Result<(), Error> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::PipInstall(format!("Failed to create dest dir: {e}")))?;
    }

    let mut response = ureq::get(url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| Error::Network(format!("Failed to fetch {url}: {e}")))?;

    let mut file = std::fs::File::create(dest)
        .map_err(|e| Error::PipInstall(format!("Failed to create {}: {e}", dest.display())))?;

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
            .map_err(|e| Error::PipInstall(format!("Failed to write file: {e}")))?;
    }

    let computed: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !computed.eq_ignore_ascii_case(expected_sha256) {
        let _ = std::fs::remove_file(dest);
        return Err(Error::BundleVerify {
            reason: format!(
                "checksum mismatch for {}\n  expected: {}\n  got:      {}",
                dest.display(),
                expected_sha256,
                computed
            ),
        });
    }

    Ok(())
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

    // Reuse the shared streaming helper; remap BundleVerify → PipInstall here
    // so the wheel-install code path keeps its existing error contract.
    if let Err(e) = stream_to_file_with_hash(&url, &dest, &wheel.sha256) {
        return match e {
            Error::BundleVerify { reason } => Err(Error::PipInstall(format!(
                "Wheel checksum mismatch: {reason}"
            ))),
            other => Err(other),
        };
    }

    eprintln!("  Checksum verified.");
    Ok(dest)
}

/// Map a CLI tag (`cli-v0.10.1`) to the version it carries (`0.10.1`).
///
/// Returns `None` for launcher tags (`v*`) and anything else.
fn cli_tag_version(tag: &str) -> Option<&str> {
    tag.strip_prefix("cli-v")
}

/// Find the newest CLI release (`cli-v*` tag) in a releases JSON array.
///
/// Ordering, draft exclusion and prerelease handling all live in
/// [`select_newest_release`] so the launcher and the CLI agree on what
/// "newest" means.
fn find_latest_cli_release(releases: &serde_json::Value) -> Option<&serde_json::Value> {
    select_newest_release(releases, cli_tag_version)
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

    use httpmock::prelude::*;

    /// `HUITZO_RELEASE_URL` is process-global. CI runs `--test-threads=1`, but
    /// a bare `cargo test` does not, so serialize the tests that set it.
    static FEED_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Point `fetch_cli_release` at `url` and return the error it produces.
    /// The guard is held for the whole call so no other test sees the variable.
    fn feed_failure(url: &str) -> Error {
        let _guard = FEED_ENV.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HUITZO_RELEASE_URL", url) };
        let result = fetch_cli_release();
        unsafe { std::env::remove_var("HUITZO_RELEASE_URL") };
        match result {
            Err(e) => e,
            Ok(r) => panic!("expected a feed failure, got release {}", r.version),
        }
    }

    fn feed_cause(url: &str) -> FeedError {
        match feed_failure(url) {
            Error::FeedUnavailable { cause, .. } => cause,
            other => panic!("expected FeedUnavailable, got: {other}"),
        }
    }

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
        assert_eq!(
            wheel.platform_key, abi_key,
            "Should prefer ABI-specific key"
        );
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
        assert_eq!(
            wheel.platform_key, platform,
            "cp313 miss → fall back to base key"
        );
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

    // --- #48: the newest cli-v* release, not the first one -----------------

    /// The real `/releases` page from #48: `cli-v0.9.0` sits at index 0,
    /// `cli-v0.10.1` at index 4, every entry shares one `created_at`, and all
    /// of them are prereleases.
    fn issue_48_releases() -> serde_json::Value {
        serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.9.0",  "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "cli-v0.8.0",  "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "v0.3.2",      "created_at": "2026-07-25T04:26:37Z", "draft": false, "prerelease": false},
                {"tag_name": "cli-v0.7.0",  "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "cli-v0.10.1", "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true},
                {"tag_name": "cli-v0.10.0", "created_at": "2026-07-20T04:26:37Z", "draft": false, "prerelease": true}
            ]"#,
        )
        .unwrap()
    }

    #[test]
    fn find_latest_cli_release_picks_newest_not_first() {
        let releases = issue_48_releases();
        let release = find_latest_cli_release(&releases).unwrap();
        assert_eq!(release["tag_name"].as_str(), Some("cli-v0.10.1"));
    }

    #[test]
    fn find_latest_cli_release_keeps_prereleases() {
        // Every cli-v* release is published as a prerelease. Filtering them
        // would leave the launcher with no CLI release at all.
        let releases: serde_json::Value = serde_json::from_str(
            r#"[{"tag_name": "cli-v0.10.1", "draft": false, "prerelease": true}]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_excludes_drafts() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.11.0", "draft": true,  "prerelease": true},
                {"tag_name": "cli-v0.10.1", "draft": false, "prerelease": true}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_ignores_launcher_tags() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "v9.9.9"}, {"tag_name": "cli-v0.10.1"}]"#)
                .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_skips_malformed_tags() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-vfoo"},
                {"tag_name": "cli-v"},
                {"tag_name": "cli-v0.10.1"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );

        let all_bad: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "cli-vfoo"}, {"tag_name": "cli-v"}]"#).unwrap();
        assert!(
            find_latest_cli_release(&all_bad).is_none(),
            "an unorderable tag must not be returned as latest"
        );
    }

    #[test]
    fn find_latest_cli_release_skips_versions_it_cannot_order() {
        // `0.11.0-rc1` truncates to [0, 11] under the lenient comparison rule,
        // which would beat 0.10.1. Selection skips it instead.
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "cli-v0.11.0-rc1"},
                {"tag_name": "cli-v0.10.1"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_cli_release(&releases).map(|r| r["tag_name"].as_str().unwrap()),
            Some("cli-v0.10.1")
        );
    }

    #[test]
    fn find_latest_cli_release_none_when_no_cli_tags() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "v0.3.2"}]"#).unwrap();
        assert!(find_latest_cli_release(&releases).is_none());
    }

    // --- manifest shape ---------------------------------------------------

    #[test]
    fn a_parsed_manifest_carries_min_launcher_version_for_t3() {
        // Not enforced here — T3 owns the gate — but it must survive parsing,
        // or T3 has nothing to enforce against without a second fetch.
        let m: serde_json::Value = serde_json::from_str(
            r#"{"version": "0.11.1", "min_launcher_version": "0.4.0",
                "wheels": {"linux-x86_64-cp313": {"filename": "w.whl", "sha256": "ab"}}}"#,
        )
        .unwrap();
        let release = parse_manifest(&m).unwrap();
        assert_eq!(release.version, "0.11.1");
        assert_eq!(release.min_launcher_version, "0.4.0");
        assert_eq!(release.wheels.len(), 1);

        // An older feed with no floor parses rather than failing the install.
        let no_floor: serde_json::Value =
            serde_json::from_str(r#"{"version": "0.9.0", "wheels": {}}"#).unwrap();
        assert_eq!(
            parse_manifest(&no_floor).unwrap().min_launcher_version,
            "0.1.0"
        );
    }

    #[test]
    fn a_manifest_without_version_or_wheels_is_rejected() {
        let no_version: serde_json::Value = serde_json::from_str(r#"{"wheels": {}}"#).unwrap();
        assert!(parse_manifest(&no_version).unwrap_err().contains("version"));
        let no_wheels: serde_json::Value = serde_json::from_str(r#"{"version": "0.1.0"}"#).unwrap();
        assert!(parse_manifest(&no_wheels).unwrap_err().contains("wheels"));
    }

    // --- M11: a feed that will not answer is never an install -------------

    #[test]
    fn a_rate_limited_feed_says_rate_limited_and_names_the_reset() {
        let server = MockServer::start();
        let reset = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 12 * 60;
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(403)
                .header("x-ratelimit-remaining", "0")
                .header("x-ratelimit-reset", reset.to_string())
                .body("{\"message\":\"API rate limit exceeded\"}");
        });

        let cause = feed_cause(&server.url("/releases"));
        assert!(
            matches!(
                cause,
                FeedError::Forbidden {
                    status: 403,
                    remaining: Some(0),
                    ..
                }
            ),
            "403 + x-ratelimit-remaining: 0 must be classified as rate limited"
        );
        let msg = cause.to_string();
        assert!(msg.contains("rate limit"), "{msg}");
        assert!(msg.contains("in 12min"), "{msg}");
        assert!(msg.contains("GITHUB_TOKEN"), "{msg}");
    }

    #[test]
    fn a_bare_403_is_still_reported_as_a_rate_limit_not_as_a_missing_wheel() {
        // An endpoint that refuses without GitHub's headers — the shape the
        // acceptance run uses. It must NOT be confused with "no wheel here".
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(403).body("forbidden");
        });

        let e = feed_failure(&server.url("/releases"));
        assert!(matches!(
            e,
            Error::FeedUnavailable {
                cause: FeedError::Forbidden {
                    status: 403,
                    remaining: None,
                    ..
                },
                ..
            }
        ));
        let msg = e.to_string();
        assert!(msg.contains("403"), "{msg}");
        assert!(msg.contains("rate limit"), "{msg}");
        assert!(msg.contains("nothing was installed"), "{msg}");
        assert!(!msg.contains("PyPI"), "no fallback may be offered: {msg}");
    }

    #[test]
    fn a_server_error_is_a_status_not_a_rate_limit() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(503).body("upstream down");
        });
        assert!(matches!(
            feed_cause(&server.url("/releases")),
            FeedError::Status(503)
        ));
    }

    #[test]
    fn a_feed_that_answers_with_html_is_malformed_not_unreachable() {
        // The #B1 failure mode applied to the feed: a 200 that is not JSON.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200).body("<!doctype html><html></html>");
        });
        let cause = feed_cause(&server.url("/releases"));
        assert!(matches!(cause, FeedError::Malformed(_)), "{cause}");
        assert!(cause.to_string().contains("not a Huitzo release feed"));
    }

    #[test]
    fn a_feed_with_no_cli_release_is_malformed_not_an_empty_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200).body(r#"[{"tag_name": "v0.3.3"}]"#);
        });
        let cause = feed_cause(&server.url("/releases"));
        assert!(cause.to_string().contains("cli-v*"), "{cause}");
    }

    #[test]
    fn a_host_that_refuses_the_connection_is_unreachable() {
        // Port 1 on loopback: nothing listens, so the connection is refused
        // immediately rather than hanging on the 30 s timeout.
        let cause = feed_cause("http://127.0.0.1:1/releases");
        assert!(matches!(cause, FeedError::Unreachable(_)), "{cause}");
        let msg = cause.to_string();
        assert!(msg.contains("never completed"), "{msg}");
        assert!(msg.contains("proxy"), "{msg}");
    }

    // --- token handling ---------------------------------------------------

    #[test]
    fn a_github_token_is_never_sent_to_a_non_github_feed() {
        let _guard = FEED_ENV.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GITHUB_TOKEN", "ghp_secret") };
        assert_eq!(
            github_token_for("https://api.github.com/repos/x/y/releases").as_deref(),
            Some("ghp_secret")
        );
        // HUITZO_RELEASE_URL can point anywhere; the token must not follow it.
        assert_eq!(github_token_for("https://evil.example/releases"), None);
        assert_eq!(github_token_for("http://127.0.0.1:8080/releases"), None);
        unsafe { std::env::remove_var("GITHUB_TOKEN") };
        assert_eq!(
            github_token_for("https://api.github.com/repos/x/y/releases"),
            None
        );
    }

    #[test]
    fn a_reset_in_the_past_is_not_rendered_as_a_wait() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(describe_reset(now - 5), None);
        assert_eq!(describe_reset(now + 30).as_deref(), Some("in 30s"));
        // 91 s rounds up to the next whole minute rather than down to 1.
        assert_eq!(describe_reset(now + 91).as_deref(), Some("in 2min"));
    }

    // --- B4: wheel-missing is its own, fully-populated error ---------------

    #[test]
    fn a_missing_wheel_names_the_platform_the_interpreter_and_the_feed() {
        // A feed that carries this platform, but only for other Pythons —
        // exactly the Python-3.11-only host in #B4.
        let platform = current_platform();
        let release = make_release(&[
            &format!("{platform}-cp313"),
            &format!("{platform}-cp312"),
            "windows-x86_64-cp312",
        ]);

        let e = find_platform_wheel(&release, Some((3, 11))).unwrap_err();
        let Error::NoWheel {
            platform: got_platform,
            python_version,
            feed_version,
            available,
        } = &e
        else {
            panic!("expected NoWheel, got: {e}");
        };
        assert_eq!(got_platform, platform);
        assert_eq!(*python_version, (3, 11));
        assert_eq!(feed_version, "0.2.3");
        // Sorted, so a user can scan it against their own key.
        let mut sorted = available.clone();
        sorted.sort();
        assert_eq!(available, &sorted);

        let msg = e.to_string();
        assert!(msg.contains("Python 3.11"), "{msg}");
        assert!(msg.contains(&format!("{platform}-cp312")), "{msg}");
        assert!(msg.contains("cli-v0.2.3"), "{msg}");
        // The actionable half: this platform IS built, just not for 3.11.
        assert!(msg.contains("3.12"), "{msg}");
        assert!(msg.contains("3.13"), "{msg}");
        assert!(!msg.contains("PyPI"), "no fallback may be offered: {msg}");
    }

    #[test]
    fn a_platform_with_no_wheels_at_all_says_so_rather_than_blaming_the_python() {
        // The #B5 / Intel-macOS shape: the feed has no build for this platform
        // at any interpreter version. T5 replaces this with the explicit
        // "Apple Silicon required" refusal; until then it must not read as
        // "install a different Python".
        let release = make_release(&["some-other-platform-cp312"]);
        let msg = find_platform_wheel(&release, Some((3, 13)))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("at any"), "{msg}");
        assert!(
            !msg.contains("Install one of those"),
            "must not suggest another Python when no build exists: {msg}"
        );
    }
}
