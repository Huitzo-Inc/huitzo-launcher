// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

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

/// Returns true if this binary was installed by Homebrew.
///
/// Homebrew installs binaries under a versioned Cellar path
/// (e.g. `/opt/homebrew/Cellar/huitzo/0.2.5/bin/huitzo`).
/// We detect this so the launcher never tries to overwrite a
/// Homebrew-managed binary — `brew upgrade huitzo` handles that.
pub fn is_homebrew_install() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .is_some_and(|s| s.contains("/Cellar/") || s.contains("/homebrew/"))
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

    // Check for launcher self-update first (higher priority).
    // Skip for Homebrew installs — replacing a Cellar binary breaks brew integrity.
    // Homebrew users get launcher updates via `brew upgrade huitzo` instead.
    if !is_homebrew_install() {
        if let Some(latest) = check_launcher_version() {
            m.pending_update = Some(PendingUpdate {
                kind: "launcher".to_string(),
                version: latest,
            });
        }
    }

    if m.pending_update.is_none() {
        if let Some(latest) = download::check_cli_release_version() {
            if version_is_newer(&latest, &m.huitzo_version) {
                m.pending_update = Some(PendingUpdate {
                    kind: "wheel".to_string(),
                    version: latest,
                });
            }
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
/// The position of a release in the array says nothing about its version
/// (see [`select_newest_release`]), so the newest is chosen by comparing
/// parsed version numbers.
fn find_latest_launcher_version(releases: &serde_json::Value) -> Option<String> {
    let tag = find_latest_launcher_release(releases)?["tag_name"].as_str()?;
    Some(launcher_tag_version(tag).unwrap_or(tag).to_string())
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

    if is_homebrew_install() {
        eprintln!("Launcher is managed by Homebrew. Run 'brew upgrade huitzo' to update.");
        return Ok(());
    }

    eprintln!("Checking for launcher updates (current: v{current_version})...");

    // 1. Fetch all releases and find the latest launcher release (v*, excluding cli-v*)
    let releases = fetch_all_releases()?;
    let release = find_latest_launcher_release(&releases).ok_or_else(|| {
        Error::SelfUpdate("No launcher release found (expected v* tag)".to_string())
    })?;

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
    select_newest_release(releases, launcher_tag_version)
}

/// Map a launcher tag (`v0.2.5`) to the version it carries (`0.2.5`).
///
/// Returns `None` for anything that is not a launcher release, including CLI
/// releases (`cli-v*`).
///
/// Which tags count as launcher releases must stay in lockstep with the
/// `livecheck` regex in the Homebrew tap — both filter on `v*`. See CLAUDE.md.
fn launcher_tag_version(tag: &str) -> Option<&str> {
    if tag.starts_with("cli-v") {
        return None;
    }
    tag.strip_prefix('v')
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

/// Parse a dotted version string into its numeric segments.
///
/// `"0.10.1"` becomes `[0, 10, 1]`, which orders correctly against
/// `[0, 9, 0]` — a string compare would not. Segments that are not plain
/// numbers are dropped, so `"0.10.1-rc1"` parses to `[0, 10]` and `"foo"`
/// to an empty vector. This is the crate's single version-comparison rule:
/// every caller that orders versions goes through it.
///
/// Release *selection* is stricter — see [`parse_release_version`] — because
/// a partially-parsed version is fine for an "is this newer?" question but
/// not for deciding which release to install.
pub(crate) fn parse_version(version: &str) -> Vec<u32> {
    version.split('.').filter_map(|s| s.parse().ok()).collect()
}

/// Parse a release tag's version, requiring **every** segment to be numeric.
///
/// Returns `None` unless every segment is one canonical decimal number, so
/// `"0.10.1-rc1"`, `"foo"`, `"+1.2.3"`, `"01.2.3"` and `""` are all rejected.
/// [`parse_version`] would silently drop the unparseable segments and rank
/// `"0.10.1-rc1"` as `[0, 10]` — below plain `0.10.1`, and tied with an
/// unrelated `0.10`. A release we cannot order in full is one we must not
/// offer as "latest", so selection skips it.
///
/// Requiring a *canonical* spelling matters as much as requiring a number:
/// two tags that differ textually but parse to the same `Vec<u32>` tie, and a
/// tie is broken by array position — the very position-dependence this
/// selection path exists to remove (#48).
fn parse_release_version(version: &str) -> Option<Vec<u32>> {
    let parsed = parse_version(version);
    // Round-trip: re-serialising the parsed numbers must reproduce the input
    // exactly. That one check covers every way `u32::from_str` is looser than
    // a release tag should be — non-numeric or empty segments, a leading `+`,
    // leading zeros — and a segment that overflows `u32`, which `parse_version`
    // drops so the rejoined string comes up short.
    let canonical = parsed
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".");
    // `parse_version("")` is empty and rejoins to `""`, which would round-trip.
    (!parsed.is_empty() && canonical == version).then_some(parsed)
}

/// Select the newest release from a GitHub releases JSON array.
///
/// `version_of` maps a `tag_name` to the version substring to compare, or
/// `None` if the tag is not the kind of release the caller wants.
///
/// Selection is by parsed version, never by position in the array. GitHub
/// sorts `/releases` by `created_at`, and every `cli-v*` release shares one
/// `created_at` (they are all tagged off the same commit), so the order among
/// them is arbitrary — trusting it pinned users on `cli-v0.9.0` while
/// `cli-v0.10.1` existed (#48).
///
/// `draft` releases are excluded. Prereleases are **not**: every `cli-v*`
/// release is published as a prerelease, so filtering them would disable CLI
/// updates entirely.
///
/// A release whose version is not wholly numeric (`cli-vfoo`, `cli-v`,
/// `cli-v0.10.1-rc1` — see [`parse_release_version`]) is skipped rather than
/// ranked, so a tag we cannot order can neither beat a well-formed newer one
/// nor be returned as "latest" when it is the only candidate.
pub(crate) fn select_newest_release<F>(
    releases: &serde_json::Value,
    version_of: F,
) -> Option<&serde_json::Value>
where
    F: Fn(&str) -> Option<&str>,
{
    releases
        .as_array()?
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(false))
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            Some((parse_release_version(version_of(tag)?)?, r))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, r)| r)
}

/// Simple version comparison: "0.2.0" > "0.1.7".
///
/// Compares numeric segments left-to-right (see [`parse_version`]).
fn version_is_newer(latest: &str, current: &str) -> bool {
    parse_version(latest) > parse_version(current)
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
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "cli-v0.5.0"}, {"tag_name": "cli-v0.4.0"}]"#)
                .unwrap();
        assert!(find_latest_launcher_release(&releases).is_none());
    }

    // --- #48: selection must be by version, never by array position ---------

    #[test]
    fn parse_version_orders_numerically_not_lexically() {
        assert_eq!(parse_version("0.10.1"), vec![0, 10, 1]);
        assert!(parse_version("0.10.1") > parse_version("0.9.0"));
        // Segments that are not numbers are dropped; a tag with no numbers at
        // all parses to an empty vector, which callers treat as "unorderable".
        assert_eq!(parse_version("foo"), Vec::<u32>::new());
        assert_eq!(parse_version(""), Vec::<u32>::new());
        assert_eq!(parse_version("0.foo.3"), vec![0, 3]);
    }

    #[test]
    fn find_latest_launcher_version_picks_newest_not_first() {
        // Mirrors the real API page from #48: newest is not at index 0, and
        // 0.10.0 must beat 0.9.0 (a string compare would get this wrong).
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "v0.9.0",  "created_at": "2026-07-20T04:26:37Z"},
                {"tag_name": "v0.8.0",  "created_at": "2026-07-20T04:26:37Z"},
                {"tag_name": "v0.10.0", "created_at": "2026-07-20T04:26:37Z"},
                {"tag_name": "v0.2.5",  "created_at": "2026-07-20T04:26:37Z"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("0.10.0")
        );
    }

    #[test]
    fn find_latest_launcher_release_picks_newest_not_first() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "v0.9.0",  "assets": []},
                {"tag_name": "v0.10.1", "assets": [{"name": "huitzo-x86_64-apple-darwin"}]}
            ]"#,
        )
        .unwrap();
        let release = find_latest_launcher_release(&releases).unwrap();
        assert_eq!(release["tag_name"].as_str(), Some("v0.10.1"));
        assert!(release["assets"].as_array().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn launcher_selection_excludes_drafts() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "v0.11.0", "draft": true},
                {"tag_name": "v0.10.1", "draft": false}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("0.10.1")
        );
    }

    #[test]
    fn launcher_selection_keeps_prereleases() {
        // Prereleases must stay eligible — every cli-v* release is marked
        // prerelease, so filtering them would disable updates entirely.
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "v0.9.0",  "prerelease": false},
                {"tag_name": "v0.10.1", "prerelease": true}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("0.10.1")
        );
    }

    #[test]
    fn launcher_selection_skips_malformed_tags() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "vfoo"},
                {"tag_name": "v"},
                {"tag_name": "v0.1.0"},
                {"tag_name": 42},
                {"no_tag": true}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("0.1.0"),
            "a malformed tag must never win over a well-formed one"
        );
    }

    #[test]
    fn launcher_selection_returns_none_when_every_tag_is_malformed() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "vfoo"}, {"tag_name": "v"}]"#).unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases),
            None,
            "an unorderable tag is skipped, not returned as latest"
        );
    }

    #[test]
    fn launcher_selection_tolerates_short_and_long_versions() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "v1.2.3.4"},
                {"tag_name": "v1.2.3"},
                {"tag_name": "v1"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("1.2.3.4")
        );
    }

    #[test]
    fn parse_release_version_requires_every_segment_to_be_numeric() {
        assert_eq!(parse_release_version("0.10.1"), Some(vec![0, 10, 1]));
        assert_eq!(parse_release_version("1"), Some(vec![1]));
        // Selection is stricter than `parse_version`, which would silently
        // truncate these and rank them as something they are not.
        assert_eq!(parse_version("0.10.1-rc1"), vec![0, 10]);
        assert_eq!(parse_release_version("0.10.1-rc1"), None);
        assert_eq!(parse_release_version("foo"), None);
        assert_eq!(parse_release_version(""), None);
        assert_eq!(parse_release_version(".1."), None);
        assert_eq!(parse_release_version("1..2"), None);
        assert_eq!(parse_release_version(" 1.2"), None);
        // `u32::from_str` accepts a leading `+`; selection must not, or
        // `v+1.2.3` would tie with `v1.2.3` and the tie would be broken by
        // array position.
        assert_eq!(parse_version("+1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_release_version("+1.2.3"), None);
        // Leading zeros are the same hazard: `u32::from_str` accepts them, so
        // `01.2.3` would parse to `[1, 2, 3]` and tie with `1.2.3`.
        assert_eq!(parse_version("01.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_release_version("01.2.3"), None);
        assert_eq!(parse_release_version("1.02.3"), None);
        assert_eq!(parse_release_version("00"), None);
        // A bare zero segment is canonical — `0.10.1` is a real tag.
        assert_eq!(parse_release_version("0.10.1"), Some(vec![0, 10, 1]));
        assert_eq!(parse_release_version("4294967295"), Some(vec![4294967295]));
        // Out of `u32` range is "not a plain number" too, so it is skipped
        // rather than silently dropping the segment and misranking the tag.
        assert_eq!(parse_release_version("4294967296.0.0"), None);
    }

    #[test]
    fn launcher_selection_never_ties_a_noncanonical_tag_with_a_plain_one() {
        // Both spellings parse to [1, 2, 3] under `parse_version`, so without
        // the canonical-spelling gate they would tie and array position would
        // decide the winner.
        for odd in ["v+1.2.3", "v01.2.3", "v1.02.3"] {
            let releases: serde_json::Value = serde_json::from_str(&format!(
                r#"[{{"tag_name": "{odd}"}}, {{"tag_name": "v1.2.3"}}]"#
            ))
            .unwrap();
            assert_eq!(
                find_latest_launcher_version(&releases).as_deref(),
                Some("1.2.3"),
                "{odd} must not be ranked as 1.2.3"
            );
        }
    }

    #[test]
    fn launcher_selection_skips_versions_it_cannot_order() {
        let releases: serde_json::Value = serde_json::from_str(
            r#"[
                {"tag_name": "v0.11.0-rc1"},
                {"tag_name": "v0.10.1"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            find_latest_launcher_version(&releases).as_deref(),
            Some("0.10.1"),
            "a suffixed tag must not be ranked as the truncated version it parses to"
        );
    }

    #[test]
    fn select_newest_release_returns_none_for_non_array() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"{"message": "Not Found"}"#).unwrap();
        assert!(select_newest_release(&releases, |t| t.strip_prefix('v')).is_none());
    }
}
