// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! Logged informed consent before any third-party install/exec.
//!
//! The one-command bootstrap installs/execs third-party binaries (the
//! Huitzo CLI, and during onboarding the AI tool + git). Before any such
//! action the launcher MUST obtain the user's informed consent and record
//! it. This mirrors the consent pattern S29 shipped on the CLI side
//! (`consent.py`, Huitzo-Inc/cli#147): an APPEND-ONLY, LOCAL-ONLY,
//! METADATA-ONLY JSONL ledger — explicitly NOT telemetry, never transmitted.
//!
//! Records carry only: timestamp, action id, the human-facing description
//! shown, and grant|decline. No secrets, no tokens, no command output, no
//! environment dumps are ever written here.
//!
//! Roadmap: docs/roadmaps/huitzo-studio.md row S55
//!          (`feat/launcher-one-command-bootstrap`); consent pattern from
//!          row S29 (`feat/runner-install-consent-log`, DONE).
//! See also: docs/architecture/huitzo-studio.md §8 (human-in-command;
//!           legal/consent items are always-required).
//!
//! NOTE: the launcher repo ships no `Implements:`-style traceability
//! convention or check script; this header is the convention this PR adds.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::dirs;
use crate::manifest::now_secs;

/// Whether the user granted or declined a consent prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Grant,
    Decline,
}

/// One append-only consent ledger entry. Metadata-only by construction —
/// there is no field that could carry a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Unix timestamp (seconds) the decision was recorded.
    pub timestamp: u64,
    /// Stable action identifier (e.g. `bootstrap_install`, `tool_install:git`).
    pub action: String,
    /// The exact human-facing description shown to the user.
    pub description: String,
    /// grant | decline.
    pub decision: Decision,
    /// Launcher version that recorded the entry (provenance).
    pub launcher_version: String,
}

/// Path to the append-only consent ledger: `<huitzo_home>/consent.jsonl`.
pub fn ledger_path() -> std::path::PathBuf {
    dirs::huitzo_home().join("consent.jsonl")
}

/// Append a consent decision to the local ledger.
///
/// Best-effort: a write failure must never block the user, so the error is
/// returned for the caller to log but the bootstrap may proceed on an
/// explicit grant regardless of ledger durability. Creates the home dir if
/// absent. Never writes anything but the metadata-only [`ConsentRecord`].
pub fn record(action: &str, description: &str, decision: Decision) -> std::io::Result<()> {
    let entry = ConsentRecord {
        timestamp: now_secs(),
        action: action.to_string(),
        description: description.to_string(),
        decision,
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let path = ledger_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Serialize WITHOUT a trailing newline, then append our own — JSONL.
    let mut line = serde_json::to_string(&entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    // This is an audit ledger — restrict to owner-only (0600) on Unix when
    // the file is first created. `.mode()` only applies on creation, so an
    // existing ledger keeps its mode; we tighten it explicitly below to
    // self-heal a pre-existing world-readable file.
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;

    // Self-heal: ensure an already-existing ledger is owner-only too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    file.write_all(line.as_bytes())
}

/// Prompt the user on the terminal for informed consent to a third-party
/// install/exec, record the decision, and return whether it was granted.
///
/// Reads a single line from stdin; anything other than an affirmative
/// (`y`/`yes`) is treated as a decline (fail-closed). When stdin is not a
/// TTY (CI, piped installs), the prompt is auto-declined UNLESS the caller
/// has set `HUITZO_ASSUME_YES=1` — an explicit, documented, non-interactive
/// override (e.g. an operator scripting a fleet install) which is itself
/// recorded as a grant in the ledger for auditability.
///
/// The decision is always logged (grant AND decline) per S29.
pub fn prompt(action: &str, description: &str) -> bool {
    use std::io::{self, BufRead};

    eprintln!();
    eprintln!("Huitzo is about to {description}.");
    eprintln!("This installs/executes third-party software on your machine.");

    let granted = if assume_yes() {
        eprintln!("  HUITZO_ASSUME_YES=1 set — proceeding with recorded consent.");
        true
    } else if !is_stdin_tty() {
        // Non-interactive without explicit override: fail closed.
        eprintln!(
            "  No interactive terminal and HUITZO_ASSUME_YES is not set — declining (fail-closed)."
        );
        false
    } else {
        eprint!("  Proceed? [y/N] ");
        let _ = io::stderr().flush();
        let mut answer = String::new();
        match io::stdin().lock().read_line(&mut answer) {
            Ok(_) => {
                let a = answer.trim().to_ascii_lowercase();
                a == "y" || a == "yes"
            }
            // Read error → fail closed.
            Err(_) => false,
        }
    };

    let decision = if granted {
        Decision::Grant
    } else {
        Decision::Decline
    };

    // Logging is best-effort; surface a warning but never abort on it.
    if let Err(e) = record(action, description, decision) {
        eprintln!("  Warning: could not write consent ledger entry: {e}");
    }

    if granted {
        eprintln!("  Consent recorded. Continuing.");
    } else {
        eprintln!("  Declined. No third-party software was installed.");
    }
    granted
}

/// Stable action id + description for the bootstrap install consent record.
pub const BOOTSTRAP_ACTION: &str = "bootstrap_install";
pub const BOOTSTRAP_DESC: &str = "download and install the Huitzo CLI into a managed environment";

/// Resolve consent for the bootstrap install, ALWAYS leaving an audit trail.
///
/// Two paths, and the invariant "no install without a recorded grant" holds
/// on both:
///   - `HUITZO_BOOTSTRAP_CONSENTED=1`: the consent prompt was already shown
///     upstream by `install.sh` / `install.ps1`. We do NOT skip silently —
///     we record the grant here (the install scripts do not write the ledger
///     themselves) and return `true`.
///   - otherwise: prompt the user (which records grant AND decline) and
///     return whether it was granted.
///
/// Returns `true` to proceed with the install, `false` if the user declined.
pub fn resolve_bootstrap_consent() -> bool {
    if std::env::var("HUITZO_BOOTSTRAP_CONSENTED").as_deref() == Ok("1") {
        // Best-effort ledger write; never block the install on durability.
        if let Err(e) = record(BOOTSTRAP_ACTION, BOOTSTRAP_DESC, Decision::Grant) {
            eprintln!("  Warning: could not write consent ledger entry: {e}");
        }
        return true;
    }
    prompt(BOOTSTRAP_ACTION, BOOTSTRAP_DESC)
}

/// Explicit non-interactive consent override (operator-scripted installs).
fn assume_yes() -> bool {
    matches!(
        std::env::var("HUITZO_ASSUME_YES").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Whether stdin is an interactive terminal.
#[cfg(unix)]
fn is_stdin_tty() -> bool {
    // SAFETY: isatty on a valid fd (0) has no preconditions beyond a valid
    // descriptor; it only reads terminal state and cannot violate memory or
    // thread invariants.
    unsafe { libc_isatty(0) == 1 }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}

#[cfg(windows)]
fn is_stdin_tty() -> bool {
    // Conservative on Windows (non-WSL is unsupported anyway): treat as
    // non-TTY so piped installs fail closed unless HUITZO_ASSUME_YES is set.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // HUITZO_HOME mutation is process-global; serialize the ledger tests.
    static LEDGER_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn record_appends_metadata_only_jsonl() {
        let _g = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by LEDGER_LOCK.
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        record(
            "bootstrap_install",
            "install the Huitzo CLI",
            Decision::Grant,
        )
        .unwrap();
        record("tool_install:git", "install git", Decision::Decline).unwrap();

        let contents = std::fs::read_to_string(ledger_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "two appended records");

        let first: ConsentRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.action, "bootstrap_install");
        assert_eq!(first.decision, Decision::Grant);
        assert_eq!(first.launcher_version, env!("CARGO_PKG_VERSION"));

        let second: ConsentRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second.decision, Decision::Decline);

        // No secret-shaped keys exist in the schema — assert the serialized
        // record carries ONLY the expected metadata fields.
        let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let obj = value.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "action",
                "decision",
                "description",
                "launcher_version",
                "timestamp"
            ]
        );

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn ledger_is_append_only_across_calls() {
        let _g = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        for i in 0..3 {
            record(&format!("action_{i}"), "desc", Decision::Grant).unwrap();
        }
        let contents = std::fs::read_to_string(ledger_path()).unwrap();
        assert_eq!(contents.lines().count(), 3);

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn decision_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Decision::Grant).unwrap(),
            "\"grant\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::Decline).unwrap(),
            "\"decline\""
        );
    }

    // BLOCKER-1 regression: HUITZO_BOOTSTRAP_CONSENTED=1 must NOT install
    // silently — it must leave a recorded Grant audit trail.
    #[test]
    fn bootstrap_consented_path_records_a_grant() {
        let _g = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by LEDGER_LOCK.
        unsafe {
            std::env::set_var("HUITZO_HOME", tmp.path());
            std::env::set_var("HUITZO_BOOTSTRAP_CONSENTED", "1");
        }

        let proceed = resolve_bootstrap_consent();
        assert!(proceed, "BOOTSTRAP_CONSENTED=1 must proceed");

        // A Grant record for the bootstrap action MUST exist.
        let contents = std::fs::read_to_string(ledger_path())
            .expect("ledger must be written on the BOOTSTRAP_CONSENTED path");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one grant recorded");
        let rec: ConsentRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec.action, BOOTSTRAP_ACTION);
        assert_eq!(rec.decision, Decision::Grant);

        unsafe {
            std::env::remove_var("HUITZO_BOOTSTRAP_CONSENTED");
            std::env::remove_var("HUITZO_HOME");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ledger_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;

        let _g = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        record(
            "bootstrap_install",
            "install the Huitzo CLI",
            Decision::Grant,
        )
        .unwrap();
        let mode = std::fs::metadata(ledger_path())
            .unwrap()
            .permissions()
            .mode();
        // Mask to the permission bits; must be exactly owner read/write.
        assert_eq!(mode & 0o777, 0o600, "consent ledger must be 0600");

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
