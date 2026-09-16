// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use crate::dirs;
use crate::download;
use crate::errors::Error;
use crate::manifest::{self, PendingUpdate};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// How many times a staged update is applied automatically before the launcher
/// stops trying on its own and waits for an explicit `huitzo --launcher-update`.
const MAX_AUTO_ATTEMPTS: u32 = 3;

/// How long to wait after a failed attempt before retrying automatically.
///
/// Matched to the update-check interval: one retry per day, not one per
/// invocation (M14).
const RETRY_AFTER_SECS: u64 = 24 * 60 * 60;

/// How many times the outgoing binary's restore is retried, and the step
/// between tries, when installing the new one failed.
///
/// A restore that does not happen leaves the user with no launcher on PATH, so
/// it is worth waiting out the transient blockers — an anti-virus scanner
/// holding the file, a handle not yet released. The permanent ones (a full
/// disk, an unwritable directory) are already ruled out before anything is
/// moved, so this loop is bounded at roughly a second and never becomes the
/// reason a launch hangs.
const RESTORE_ATTEMPTS: u32 = 5;
const RESTORE_BACKOFF_MS: u64 = 100;

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

/// Run the update check synchronously, waiting at most 5 seconds for it.
///
/// The 5 seconds bound the *user's* wait, not the request: `recv_timeout`
/// abandons the waiter and returns, it does not cancel anything, and the
/// spawned thread keeps running until `execvp` replaces the process. The
/// requests are bounded separately and for real, by the timeouts
/// [`crate::download::http_agent`] puts on every call (M12) — without those a
/// blackholed host left that thread alive with no way to end.
///
/// Blocking here at all is deliberate: it guarantees the manifest is written
/// before `execvp` kills any detached thread.
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
            m.pending_update = Some(stage(m.pending_update.take(), "launcher", latest));
        }
    }

    // A staged launcher update takes precedence: it is the one that can change
    // what the CLI update is even allowed to be (see
    // [`enforce_min_launcher_version`]). Anything else staged is a CLI update,
    // and re-checking it lets a genuinely newer release replace one that is
    // stuck — without resetting the attempt count when it is the same release.
    let launcher_staged = m
        .pending_update
        .as_ref()
        .is_some_and(|p| p.kind == "launcher");
    if !launcher_staged {
        if let Some(latest) = download::check_cli_release_version() {
            if version_is_newer(&latest, &m.huitzo_version) {
                m.pending_update = Some(stage(m.pending_update.take(), "wheel", latest));
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
    let mut response = download::http_agent(download::FEED_BUDGET)?
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| {
            Error::Network(format!(
                "GitHub API request failed: {}",
                download::transport_failure(&e, download::FEED_BUDGET)
            ))
        })?;

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

/// What a self-update attempt actually did.
///
/// The distinction is the fix for M13: [`self_update`] used to answer `Ok(())`
/// to "installed 0.3.3", "already on 0.3.3" and "Homebrew owns this binary, I
/// did nothing" alike, and the caller wrote `launcher_version = <target>` into
/// the manifest for all three. A brew user's manifest then claimed a version
/// they did not have.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The binary on disk was replaced. Carries the version now installed —
    /// the only value a caller may record as `launcher_version`.
    Updated(String),
    /// Already running the newest release; nothing was written.
    AlreadyCurrent,
    /// Homebrew owns this binary and `brew upgrade huitzo` is the only safe
    /// way to move it. **Nothing was installed.**
    DeferredToHomebrew,
}

/// Self-update the launcher binary from GitHub Releases.
///
/// Filters the releases list for `v*` tags (excludes `cli-v*`) so that a CLI
/// release published after the latest launcher release does not shadow it.
/// Verifies integrity, then replaces the running binary via
/// [`replace_running_binary`].
pub fn self_update() -> Result<UpdateOutcome, Error> {
    let current_version = env!("CARGO_PKG_VERSION");

    if is_homebrew_install() {
        eprintln!(
            "Launcher is managed by Homebrew — not replacing {}.\n\
             Run 'brew upgrade huitzo' to update it.",
            std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "the installed binary".to_string())
        );
        return Ok(UpdateOutcome::DeferredToHomebrew);
    }

    // The previous image, if an update on this machine left one behind
    // (Windows cannot delete the binary it is running from).
    cleanup_replaced_binary();

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
        return Ok(UpdateOutcome::AlreadyCurrent);
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

    // The suffix is not cosmetic: on Windows an extensionless file is not an
    // executable image, so the binary must already be `huitzo-new.exe` before
    // it is moved into place (m13).
    let tmp_binary = tmp_dir.join(format!("huitzo-new{}", std::env::consts::EXE_SUFFIX));

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
    if let Err(e) = replace_running_binary(&tmp_binary, &current_exe) {
        // Leaving a verified-but-uninstalled binary in tmp would be re-used by
        // nothing and re-downloaded anyway; drop it so a retry starts clean.
        let _ = std::fs::remove_file(&tmp_binary);
        return Err(e);
    }

    eprintln!("Launcher updated to v{latest_version} successfully.");
    Ok(UpdateOutcome::Updated(latest_version.to_string()))
}

/// Put `new_binary` in place of the currently running executable.
///
/// `std::fs::rename(new, current_exe)` — what this used to do — fails outright
/// on Windows, which refuses to replace a mapped image: `Access is denied.
/// (os error 5)`, and the founder's install sat on 0.3.2 because of it (B6).
///
/// Windows *does* allow a running image to be **renamed**, so the sequence is:
/// stage the new binary beside the running one, move the running one aside to
/// `<exe>.old`, rename the staged file into its place, then delete the old one
/// — which succeeds immediately on Unix and on the next launch on Windows
/// ([`cleanup_replaced_binary`]).
///
/// Staging into the destination directory *first* is what keeps a half-done
/// replacement off the user's disk. It is the only step that moves bytes, so
/// it is where a full disk, an unwritable directory or a scanner refusing the
/// write surfaces — and it surfaces with the working launcher still exactly
/// where it was. What is left after it are two same-directory renames: they
/// need no space, they cannot leave a truncated file behind, and a failed one
/// is retried ([`restore_with_retry`]) rather than accepted. An out-of-date
/// launcher is recoverable; a missing one is not.
fn replace_running_binary(new_binary: &Path, current_exe: &Path) -> Result<(), Error> {
    let backup = backup_path(current_exe);
    let staged = staged_path(current_exe);
    // Windows `rename` never overwrites, so leftovers from an earlier update
    // would fail the moves below before they started.
    let _ = std::fs::remove_file(&backup);
    let _ = std::fs::remove_file(&staged);

    if let Err(e) = move_file(new_binary, &staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(Error::SelfUpdate(format!(
            "Could not write the new binary into {}, so the update was not started \
             and the launcher at {} is untouched: {e}",
            current_exe.parent().unwrap_or(current_exe).display(),
            current_exe.display()
        )));
    }

    if let Err(e) = std::fs::rename(current_exe, &backup) {
        let _ = std::fs::remove_file(&staged);
        return Err(Error::SelfUpdate(format!(
            "Failed to move the running binary aside ({} -> {}), so it is untouched: {e}",
            current_exe.display(),
            backup.display()
        )));
    }

    // A rename either happens or does not: unlike a copy it cannot leave a
    // truncated image at `current_exe`, so the restore below has a clear path.
    if let Err(e) = std::fs::rename(&staged, current_exe) {
        let restored = restore_with_retry(&backup, current_exe);
        let _ = std::fs::remove_file(&staged);
        return Err(Error::SelfUpdate(format!(
            "Failed to install the new binary at {}: {e}{}",
            current_exe.display(),
            if restored {
                " (the previous launcher was put back and still works)"
            } else {
                // Say it plainly rather than let the next run look like a
                // mysteriously missing command.
                " — and the previous launcher could not be restored; it is at the .old path beside it"
            }
        )));
    }

    // Unix unlinks it here; Windows still has the image mapped and refuses,
    // which is what `cleanup_replaced_binary` is for.
    let _ = std::fs::remove_file(&backup);
    Ok(())
}

/// Put the outgoing binary back after a failed install, retrying briefly.
///
/// The blockers that can still reach this point are transient by construction
/// — the permanent ones failed the staging step before anything moved — and a
/// launcher that exists is worth a second of backoff. Returns whether the
/// binary is back in place; the caller reports the outcome either way, and
/// only ever from this return value: a `current_exe` that merely *exists*
/// could be the half-installed image, which is not a working launcher.
fn restore_with_retry(backup: &Path, current_exe: &Path) -> bool {
    for attempt in 0..RESTORE_ATTEMPTS {
        if std::fs::rename(backup, current_exe).is_ok() {
            return true;
        }
        if attempt + 1 < RESTORE_ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_millis(
                RESTORE_BACKOFF_MS * u64::from(attempt + 1),
            ));
        }
    }
    false
}

/// Where the outgoing binary is parked during a replacement: `<exe>.old`
/// (`huitzo.exe.old` on Windows, `huitzo.old` elsewhere).
fn backup_path(current_exe: &Path) -> PathBuf {
    let mut name = current_exe.as_os_str().to_os_string();
    name.push(".old");
    PathBuf::from(name)
}

/// Where the incoming binary is written before the swap: `<exe>.new`, in the
/// install directory on purpose — see [`replace_running_binary`]. Neither
/// suffix is executable by PATH lookup, so a leftover can never be run in
/// place of the real launcher.
fn staged_path(current_exe: &Path) -> PathBuf {
    let mut name = current_exe.as_os_str().to_os_string();
    name.push(".new");
    PathBuf::from(name)
}

/// Delete the previous binary left behind by an update on this machine.
///
/// Called at the start of every self-update and once per launch from the
/// pending-update path. On Windows the `.old` file cannot be deleted by the
/// process that was running from it, so it is always the *next* launch that
/// clears it.
pub fn cleanup_replaced_binary() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(backup_path(&exe));
        // A staged binary from an update that died mid-swap is dead weight:
        // the next update writes its own. Left alone it would accumulate one
        // copy of the launcher per failed attempt.
        let _ = std::fs::remove_file(staged_path(&exe));
    }
}

/// Move `from` to `to`, falling back to copy + delete when `rename` cannot
/// cross the boundary between them.
///
/// `$HUITZO_HOME/tmp` and the installed binary are routinely on different
/// filesystems — a `/tmp`-backed `HUITZO_HOME`, a container bind mount, a
/// Windows install on a different drive from the download directory — and
/// `rename` answers `EXDEV` there (m13). A failure the copy shares (no
/// permission on the destination, no space) still surfaces: the copy reports
/// it.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            // `copy` carries the Unix mode bits across, so the 0o755 set on the
            // download survives the fallback.
            std::fs::copy(from, to)?;
            let _ = std::fs::remove_file(from);
            Ok(())
        }
    }
}

/// Stage `kind`/`version` as the pending update, carrying an existing failure
/// record forward when it is the same update that is already staged.
///
/// Without this the daily check would zero the attempt counter and the bounded
/// retry would never be bounded — the loop M14 describes, just one day long.
fn stage(existing: Option<PendingUpdate>, kind: &str, version: String) -> PendingUpdate {
    match existing {
        Some(p) if p.kind == kind && p.version == version => p,
        _ => PendingUpdate {
            kind: kind.to_string(),
            version,
            attempts: 0,
            last_attempt: 0,
            last_error: None,
        },
    }
}

/// Whether a staged update should be applied automatically on this launch.
///
/// First attempt: always. After a failure: not again until `RETRY_AFTER_SECS`
/// has passed, and never more than `MAX_AUTO_ATTEMPTS` times in total. An
/// explicit `huitzo --launcher-update` does not come through here — a user who
/// asks for a retry gets one.
pub fn should_attempt(pending: &PendingUpdate, now: u64) -> bool {
    if pending.attempts == 0 {
        return true;
    }
    pending.attempts < MAX_AUTO_ATTEMPTS
        && now.saturating_sub(pending.last_attempt) >= RETRY_AFTER_SECS
}

/// The line printed when an update is staged but not attempted.
///
/// Silence here would be the other half of the M14 bug: the launcher would
/// simply stop updating with no way for the user to find out why. The message
/// names the failure and the command that retries it.
pub fn deferral_notice(pending: &PendingUpdate) -> String {
    let what = if pending.kind == "launcher" {
        format!("launcher update to v{}", pending.version)
    } else {
        format!("huitzo update to {}", pending.version)
    };
    let cause = pending
        .last_error
        .as_deref()
        .filter(|e| !e.is_empty())
        .map(|e| format!(" (last error: {e})"))
        .unwrap_or_default();
    let plural = if pending.attempts == 1 { "" } else { "s" };
    format!(
        "huitzo: {what} deferred after {} failed attempt{plural}{cause}. \
         Retry with '{}'.",
        pending.attempts,
        if pending.kind == "launcher" {
            upgrade_instruction()
        } else {
            "huitzo --launcher-bootstrap".to_string()
        }
    )
}

/// Record a failed attempt against the staged update so the next launch does
/// not repeat it immediately (M14).
///
/// Only the record that actually failed is touched: a check that ran in
/// between may have staged a different one, and charging that one for this
/// failure would be a lie in the manifest.
pub fn record_failed_attempt(kind: &str, version: &str, error: &str) {
    let Some(mut m) = manifest::load() else {
        return;
    };
    match m.pending_update {
        Some(ref mut p) if p.kind == kind && p.version == version => {
            p.attempts = p.attempts.saturating_add(1);
            p.last_attempt = manifest::now_secs();
            p.last_error = Some(summarize(error));
        }
        _ => return,
    }
    let _ = manifest::save(&m);
}

/// Clear the staged update, recording a new `launcher_version` only when one
/// was actually installed.
///
/// `installed_launcher_version` is `None` for every outcome that did not write
/// a binary — including the Homebrew deferral (M13).
pub fn settle_pending(installed_launcher_version: Option<&str>) {
    let Some(mut m) = manifest::load() else {
        return;
    };
    m.pending_update = None;
    if let Some(version) = installed_launcher_version {
        m.launcher_version = version.to_string();
    }
    let _ = manifest::save(&m);
}

/// First line of an error, bounded, for storage in the manifest.
fn summarize(error: &str) -> String {
    let line = error.lines().next().unwrap_or_default().trim();
    if line.chars().count() > 200 {
        line.chars().take(197).chain("...".chars()).collect()
    } else {
        line.to_string()
    }
}

/// Refuse to install from a CLI release that requires a newer launcher (M10).
///
/// The feed publishes `min_launcher_version` so a CLI build that depends on
/// launcher behaviour — an exec contract, a manifest field, a bundle layout —
/// is never installed under a launcher that lacks it. Until now the floor was
/// parsed and dropped (`download.rs` carried it behind `#[allow(dead_code)]`),
/// which made it documentation rather than a control.
///
/// A floor this launcher cannot parse (`""`, `"latest"`) compares as not-newer
/// and is allowed through: a malformed field in the feed must not brick every
/// install, and the wheel is still SHA-256 verified either way.
pub fn enforce_min_launcher_version(release: &download::CliRelease) -> Result<(), Error> {
    let current = env!("CARGO_PKG_VERSION");
    if !version_is_newer(&release.min_launcher_version, current) {
        return Ok(());
    }
    Err(Error::LauncherTooOld {
        launcher: current.to_string(),
        required: release.min_launcher_version.clone(),
        feed_version: release.version.clone(),
        remedy: upgrade_instruction(),
    })
}

/// The command that updates *this* installation's launcher.
///
/// A Homebrew install must never be told to run `huitzo --launcher-update`:
/// that path deliberately refuses to touch a Cellar binary, so the advice
/// would be a dead end.
pub fn upgrade_instruction() -> String {
    if is_homebrew_install() {
        "brew upgrade huitzo".to_string()
    } else {
        "huitzo --launcher-update".to_string()
    }
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
    // A checksum file is a single line, so it gets the small-request budget.
    let mut response = download::http_agent(download::FEED_BUDGET)?
        .get(url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| {
            Error::Network(format!(
                "Failed to download checksum: {}",
                download::transport_failure(&e, download::FEED_BUDGET)
            ))
        })?;

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
    // The launcher binary is a multi-megabyte artefact: the download budget,
    // not the feed one.
    let mut response = download::http_agent(download::DOWNLOAD_BUDGET)?
        .get(url)
        .header("User-Agent", "huitzo-launcher")
        .call()
        .map_err(|e| {
            Error::Network(format!(
                "Failed to download binary: {}",
                download::transport_failure(&e, download::DOWNLOAD_BUDGET)
            ))
        })?;

    let mut file = std::fs::File::create(dest)
        .map_err(|e| Error::SelfUpdate(format!("Failed to create temp file: {e}")))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut written: u64 = 0;
    let mut reader = response.body_mut().as_reader();

    loop {
        // Inside the same global budget as the request that opened this body,
        // so a stalled transfer ends here instead of hanging the update.
        let n = reader.read(&mut buf).map_err(|e| {
            Error::Network(format!(
                "Download of {url} interrupted after {written} bytes: {e}\n\
                 \x20 The whole download must finish within {}s.",
                download::DOWNLOAD_BUDGET.global_secs()
            ))
        })?;
        if n == 0 {
            break;
        }
        written += n as u64;
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

    // --- B6 / m13: replacing a binary that is currently running -----------

    fn write(path: &std::path::Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn backup_path_appends_old_to_the_whole_file_name() {
        // `.exe.old`, not `.old` replacing `.exe`: `with_extension` would have
        // produced `huitzo.old`, which on Windows is not the image we renamed.
        assert_eq!(
            backup_path(std::path::Path::new("/opt/huitzo/bin/huitzo.exe")),
            std::path::PathBuf::from("/opt/huitzo/bin/huitzo.exe.old")
        );
        assert_eq!(
            backup_path(std::path::Path::new("/usr/local/bin/huitzo")),
            std::path::PathBuf::from("/usr/local/bin/huitzo.old")
        );
    }

    #[test]
    fn replacing_the_running_binary_installs_the_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir
            .path()
            .join(format!("huitzo{}", std::env::consts::EXE_SUFFIX));
        let new = dir.path().join("huitzo-new");
        write(&exe, "old binary");
        write(&new, "new binary");

        replace_running_binary(&new, &exe).unwrap();

        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "new binary");
        assert!(!new.exists(), "the staged binary should have been consumed");
        assert!(
            !backup_path(&exe).exists(),
            "the outgoing binary is unlinked here on Unix"
        );
        assert!(
            !staged_path(&exe).exists(),
            "the staging file is consumed by the swap"
        );
    }

    #[test]
    fn replacing_over_a_leftover_backup_succeeds() {
        // Windows `rename` refuses to overwrite, so a `.old` left by an
        // earlier update would block the move-aside if it were not cleared.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("huitzo");
        let new = dir.path().join("huitzo-new");
        write(&exe, "v2");
        write(&backup_path(&exe), "v1");
        // And a staged file from an update that died mid-swap.
        write(&staged_path(&exe), "half a binary");
        write(&new, "v3");

        replace_running_binary(&new, &exe).unwrap();
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "v3");
    }

    #[test]
    fn a_failed_replacement_never_touches_the_installed_binary() {
        // The half-done state — running image moved aside, new one not
        // installed — must never be what the user is left with. A new binary
        // that cannot be staged fails before anything is moved.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("huitzo");
        write(&exe, "old binary");
        let missing = dir.path().join("does-not-exist");

        let err = replace_running_binary(&missing, &exe).unwrap_err();
        assert!(
            format!("{err}").contains("untouched"),
            "unexpected message: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&exe).unwrap(),
            "old binary",
            "an out-of-date launcher is recoverable; a missing one is not"
        );
        assert!(
            !backup_path(&exe).exists(),
            "nothing should have been moved aside"
        );
        assert!(
            !staged_path(&exe).exists(),
            "the staging file must be cleaned up"
        );
    }

    /// The brick the review reproduced: a destination directory that cannot be
    /// written used to fail *after* the running binary had been moved aside,
    /// and the restore failed for the same reason, leaving no launcher at all.
    /// Staging first turns that into an update that simply did not happen.
    #[test]
    #[cfg(unix)]
    fn an_unwritable_destination_leaves_the_launcher_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("huitzo");
        write(&exe, "old binary");
        let new = dir.path().join("huitzo-new");
        write(&new, "new binary");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root ignores the permission bits this test's premise rests on, so
        // probe the directory rather than the uid: if it is still writable
        // there is nothing here to assert.
        let probe = dir.path().join(".probe");
        if std::fs::write(&probe, "x").is_ok() {
            let _ = std::fs::remove_file(&probe);
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let err = replace_running_binary(&new, &exe).unwrap_err();

        // Restore permissions before asserting so a failure still cleans up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            format!("{err}").contains("untouched"),
            "the user must be told the update did not start: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&exe).unwrap(),
            "old binary",
            "the working launcher must still be exactly where it was"
        );
        assert!(
            !backup_path(&exe).exists(),
            "the running binary must not have been moved aside"
        );
    }

    /// Same guarantee without depending on permission bits at all: something
    /// occupying the staged path that cannot be overwritten fails the
    /// pre-flight, and the installed binary is never disturbed.
    #[test]
    fn a_blocked_staging_path_leaves_the_launcher_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("huitzo");
        write(&exe, "old binary");
        let new = dir.path().join("huitzo-new");
        write(&new, "new binary");
        // A directory cannot be replaced by `rename` or written by `copy`,
        // whatever the uid.
        std::fs::create_dir(staged_path(&exe)).unwrap();

        let err = replace_running_binary(&new, &exe).unwrap_err();
        assert!(format!("{err}").contains("untouched"), "{err}");
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old binary");
        assert!(!backup_path(&exe).exists());
    }

    #[test]
    fn the_restore_puts_the_outgoing_binary_back() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("huitzo");
        let backup = backup_path(&exe);
        write(&backup, "old binary");

        assert!(restore_with_retry(&backup, &exe));
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old binary");
        assert!(!backup.exists());
    }

    #[test]
    fn the_restore_gives_up_instead_of_spinning() {
        // A restore that genuinely cannot succeed must terminate — the caller
        // reports the `.old` path so the user can recover by hand.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("huitzo");
        let absent = backup_path(&exe);

        let started = std::time::Instant::now();
        assert!(!restore_with_retry(&absent, &exe));
        assert!(
            !exe.exists(),
            "nothing was restored, and nothing was invented"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the backoff must stay bounded"
        );
    }

    /// The EXDEV case (m13) with a real filesystem boundary: `/dev/shm` and
    /// the tempdir are always separate mounts on Linux, so `rename` between
    /// them genuinely fails and the copy fallback is what completes the move.
    #[test]
    #[cfg(target_os = "linux")]
    fn moving_a_binary_across_filesystems_falls_back_to_copy() {
        let shm = std::path::Path::new("/dev/shm");
        if !shm.is_dir() {
            return;
        }
        let src = shm.join(format!("huitzo-t3-{}", std::process::id()));
        write(&src, "new binary");
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("huitzo");

        let rename = std::fs::rename(&src, &dest).unwrap_err();
        assert_eq!(
            rename.raw_os_error(),
            Some(18),
            "expected EXDEV across /dev/shm; got {rename}"
        );

        move_file(&src, &dest).unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "new binary");
        assert!(!src.exists(), "the source should not be left behind");
    }

    #[test]
    #[cfg(unix)]
    fn the_copy_fallback_keeps_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dest = dir.path().join("dest");
        write(&src, "binary");
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Force the fallback by leaving `rename` nothing to do differently:
        // copy directly, which is exactly the branch `move_file` takes.
        std::fs::copy(&src, &dest).unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o111,
            0o111,
            "copied binary is not executable: {mode:o}"
        );
    }

    #[test]
    fn the_staged_binary_carries_the_platform_executable_suffix() {
        // Windows will not execute an extensionless file, so `huitzo-new`
        // could not be the thing we move into place (m13).
        let name = format!("huitzo-new{}", std::env::consts::EXE_SUFFIX);
        if cfg!(windows) {
            assert_eq!(name, "huitzo-new.exe");
        } else {
            assert_eq!(name, "huitzo-new");
        }
    }

    // --- M14: a failed update settles -------------------------------------

    fn pending(kind: &str, version: &str, attempts: u32, last_attempt: u64) -> PendingUpdate {
        PendingUpdate {
            kind: kind.to_string(),
            version: version.to_string(),
            attempts,
            last_attempt,
            last_error: Some("Access is denied. (os error 5)".to_string()),
        }
    }

    #[test]
    fn a_fresh_update_is_attempted_immediately() {
        let p = pending("launcher", "0.3.3", 0, 0);
        assert!(should_attempt(&p, 1_000_000));
    }

    #[test]
    fn the_invocation_after_a_failure_does_not_retry() {
        // This is M14 itself: the run right after a failure must not
        // re-download the same binary.
        let now = 1_000_000;
        let p = pending("launcher", "0.3.3", 1, now);
        assert!(!should_attempt(&p, now));
        assert!(!should_attempt(&p, now + RETRY_AFTER_SECS - 1));
        assert!(should_attempt(&p, now + RETRY_AFTER_SECS));
    }

    #[test]
    fn automatic_retries_are_bounded() {
        let now = 1_000_000;
        let capped = pending("launcher", "0.3.3", MAX_AUTO_ATTEMPTS, now);
        assert!(
            !should_attempt(&capped, now + 10 * RETRY_AFTER_SECS),
            "a permanently failing update must stop retrying on its own"
        );
    }

    #[test]
    fn a_deferral_says_what_failed_and_how_to_retry() {
        let notice = deferral_notice(&pending("launcher", "0.3.3", 2, 0));
        assert!(notice.contains("0.3.3"), "{notice}");
        assert!(notice.contains("2 failed attempts"), "{notice}");
        assert!(notice.contains("Access is denied"), "{notice}");
        assert!(notice.contains("--launcher-update"), "{notice}");
        // Singular reads right too — the common case is one failure.
        let mut once = pending("launcher", "0.3.3", 1, 0);
        once.last_error = None;
        let singular = deferral_notice(&once);
        assert!(
            singular.contains("1 failed attempt."),
            "expected singular phrasing: {singular}"
        );
    }

    #[test]
    fn re_staging_the_same_update_keeps_its_failure_record() {
        // Otherwise the daily check resets the counter and the bounded retry
        // is unbounded again.
        let existing = pending("launcher", "0.3.3", 2, 555);
        let staged = stage(Some(existing), "launcher", "0.3.3".to_string());
        assert_eq!(staged.attempts, 2);
        assert_eq!(staged.last_attempt, 555);
    }

    #[test]
    fn staging_a_different_version_starts_a_fresh_record() {
        let staged = stage(
            Some(pending("launcher", "0.3.3", 3, 555)),
            "launcher",
            "0.3.4".to_string(),
        );
        assert_eq!(staged.version, "0.3.4");
        assert_eq!(staged.attempts, 0);
        assert!(staged.last_error.is_none());

        let kind_changed = stage(
            Some(pending("wheel", "0.3.3", 3, 555)),
            "launcher",
            "0.3.3".to_string(),
        );
        assert_eq!(kind_changed.attempts, 0);
    }

    #[test]
    fn a_stored_failure_is_one_bounded_line() {
        let multiline = "first line\nsecond line";
        assert_eq!(summarize(multiline), "first line");
        let long = "x".repeat(500);
        let stored = summarize(&long);
        assert_eq!(stored.chars().count(), 200);
        assert!(stored.ends_with("..."));
    }

    // --- M10: the release feed's launcher floor ---------------------------

    fn release_with_floor(floor: &str) -> download::CliRelease {
        download::CliRelease {
            version: "0.11.1".to_string(),
            min_launcher_version: floor.to_string(),
            wheels: Vec::new(),
        }
    }

    #[test]
    fn a_release_that_requires_a_newer_launcher_is_refused() {
        let err = enforce_min_launcher_version(&release_with_floor("99.0.0")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("99.0.0"), "{msg}");
        assert!(msg.contains(env!("CARGO_PKG_VERSION")), "{msg}");
        assert!(msg.contains("0.11.1"), "{msg}");
        assert!(
            msg.contains("--launcher-update") || msg.contains("brew upgrade"),
            "the refusal must name a way out: {msg}"
        );
        assert_eq!(crate::errors::exit_code(&err), 78);
    }

    #[test]
    fn a_release_at_or_below_the_launcher_version_is_allowed() {
        let current = env!("CARGO_PKG_VERSION");
        enforce_min_launcher_version(&release_with_floor(current))
            .expect("a floor equal to this launcher must pass");
        enforce_min_launcher_version(&release_with_floor("0.1.0"))
            .expect("an older floor must pass");
        // The default `parse_manifest` applies when the feed predates the field.
        enforce_min_launcher_version(&release_with_floor("0.0.1")).unwrap();
    }

    #[test]
    fn an_unparseable_floor_does_not_brick_every_install() {
        for floor in ["", "latest", "not-a-version"] {
            enforce_min_launcher_version(&release_with_floor(floor))
                .unwrap_or_else(|e| panic!("floor {floor:?} must not refuse: {e}"));
        }
    }

    #[test]
    fn select_newest_release_returns_none_for_non_array() {
        let releases: serde_json::Value =
            serde_json::from_str(r#"{"message": "Not Found"}"#).unwrap();
        assert!(select_newest_release(&releases, |t| t.strip_prefix('v')).is_none());
    }
}
