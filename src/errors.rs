// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use std::fmt;

use crate::python::MIN_PYTHON;
use crate::uv::PROVISIONED_PYTHON;

/// Indent a captured subprocess stderr block so it reads as quoted output
/// rather than as more of the launcher's own prose.
fn indent(detail: &str) -> String {
    let trimmed = detail.trim_end();
    if trimmed.is_empty() {
        return "    (no output)".to_string();
    }
    trimmed
        .lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Launcher error types with user-facing messages.
pub enum Error {
    /// No usable Python 3.11+ interpreter could be found OR provisioned.
    ///
    /// `searched` lists what discovery actually looked at; `provision` carries
    /// the reason `uv python install` could not supply one. With D1 the
    /// launcher provisions its own CPython, so "not installed on this host" is
    /// no longer a cause on its own — one of these two fields always names the
    /// real one.
    NoPython {
        searched: Vec<String>,
        provision: Option<String>,
    },
    /// `uv venv` failed for a specific interpreter.
    VenvCreate { interpreter: String, detail: String },
    /// The existing managed venv could not be removed.
    VenvRemove(String),
    /// `uv` — a hard dependency of first run since D1 — could not be staged.
    UvUnavailable(String),
    /// pip install failed.
    PipInstall(String),
    /// HTTP request failed (PyPI, GitHub).
    Network(String),
    /// manifest.json read/write failed.
    Manifest(String),
    /// Self-update failed.
    SelfUpdate(String),
    /// exec() failed.
    Exec(String),
    /// Deployment-root key fingerprint mismatch on TOFU verification.
    /// Critical security event; refuse to continue.
    TrustViolation { stored: String, advertised: String },
    /// Bundle integrity / signature verification failed.
    BundleVerify { reason: String },
    /// User declined the informed-consent prompt before a third-party
    /// install/exec. A deliberate user choice, NOT a failure — rendered and
    /// exit-coded distinctly from install/network errors so scripts can tell
    /// "user declined" from "install broke".
    ConsentDeclined,
    /// A `huitzo-cli` source checkout was detected but no local environment
    /// can run it (#53). Delegating to the managed venv here would silently
    /// run a different version of the CLI than the caller believes, so the
    /// launcher refuses and names both paths instead.
    LocalCliUnavailable {
        checkout: String,
        managed: String,
        searched: Vec<String>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoPython {
                searched,
                provision,
            } => {
                let min = format!("{}.{}", MIN_PYTHON.0, MIN_PYTHON.1);
                let searched = if searched.is_empty() {
                    "    (nothing on PATH matched)".to_string()
                } else {
                    searched
                        .iter()
                        .map(|p| format!("    {p}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                match provision {
                    // The launcher tried to download its own CPython and that
                    // is what failed. Naming `uv python install` is the whole
                    // point: "install Python yourself" would be wrong advice.
                    Some(detail) => write!(
                        f,
                        "No usable Python {min}+ interpreter, and one could not be downloaded.\n\n\
                         \x20 Interpreters examined:\n{searched}\n\
                         \x20 `uv python install {PROVISIONED_PYTHON}` failed:\n    {detail}\n\n\
                         The launcher downloads its own Python, so this is a network, proxy or\n\
                         disk-space problem rather than a missing system Python. Retry once the\n\
                         connection is available; nothing was installed."
                    ),
                    None => write!(
                        f,
                        "No usable Python {min}+ interpreter could be selected.\n\n\
                         \x20 Interpreters examined:\n{searched}"
                    ),
                }
            }
            Error::VenvCreate {
                interpreter,
                detail,
            } => write!(
                f,
                "Failed to create the managed virtual environment.\n\n\
                 \x20 Interpreter: {interpreter}\n\
                 \x20 `uv venv` reported:\n{}\n\n\
                 The managed venv is built by `uv venv`, which does not use `ensurepip` —\n\
                 a distro `python3-venv` package is NOT the missing piece. The partial venv\n\
                 was removed, so re-running `huitzo` starts clean; if it keeps failing,\n\
                 report the `uv venv` output above at\n\
                 https://github.com/Huitzo-Inc/huitzo-launcher/issues",
                indent(detail)
            ),
            Error::VenvRemove(detail) => write!(
                f,
                "Could not remove the existing managed environment.\n{detail}\n\n\
                 Check the permissions on $HUITZO_HOME (default ~/.huitzo)."
            ),
            Error::UvUnavailable(detail) => write!(
                f,
                "Could not set up uv, which the launcher needs to build its Python\n\
                 environment.\n\n\
                 \x20 {detail}\n\n\
                 uv is downloaded from https://github.com/astral-sh/uv/releases — check your\n\
                 network or proxy and retry. Nothing was installed."
            ),
            Error::PipInstall(detail) => write!(
                f,
                "Package installation failed.\n{detail}\n\n\
                 Check your internet connection and try: huitzo --launcher-bootstrap"
            ),
            Error::Network(detail) => write!(f, "Network error: {detail}"),
            Error::Manifest(detail) => write!(f, "Manifest error: {detail}"),
            Error::SelfUpdate(detail) => write!(
                f,
                "Self-update failed: {detail}\n\n\
                 Update manually: https://github.com/Huitzo-Inc/huitzo-launcher/releases"
            ),
            Error::Exec(detail) => write!(f, "Failed to exec into Python CLI: {detail}"),
            Error::TrustViolation { stored, advertised } => write!(
                f,
                "Deployment trust mismatch\n\
                 \x20 Stored fingerprint:    {stored}\n\
                 \x20 Advertised fingerprint: {advertised}\n\n\
                 This is a CRITICAL security event. Refusing to install bundle.\n\
                 If you trust this rotation, run:\n\
                 \x20 huitzo --launcher-trust-rotate"
            ),
            Error::BundleVerify { reason } => write!(
                f,
                "Bundle verification failed: {reason}\n\n\
                 Refusing to install untrusted bundle."
            ),
            Error::ConsentDeclined => write!(
                f,
                "Installation declined. No third-party software was installed."
            ),
            Error::LocalCliUnavailable {
                checkout,
                managed,
                searched,
            } => {
                // `searched` is never empty as `Decision::Refuse` is built
                // today (the checkout's own `.venv` is always a candidate);
                // the branch keeps the message well-formed rather than being
                // load-bearing.
                let searched = if searched.is_empty() {
                    "    (none)".to_string()
                } else {
                    searched
                        .iter()
                        .map(|p| format!("    {p}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                write!(
                    f,
                    "Refusing to run the managed CLI from a huitzo-cli source checkout.\n\n\
                     \x20 Checkout detected: {checkout}\n\
                     \x20 Would have run:    {managed}\n\
                     \x20 No local huitzo_cli found in:\n{searched}\n\n\
                     Install the checkout's environment (e.g. `uv sync`), or run the\n\
                     managed CLI deliberately:\n\
                     \x20 huitzo --use-installed <command>   (or HUITZO_LAUNCHER_FORCE=1)"
                )
            }
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Exit codes following sysexits.h conventions.
pub fn exit_code(err: &Error) -> i32 {
    match err {
        Error::NoPython { .. } => 78,   // EX_CONFIG
        Error::VenvCreate { .. } => 73, // EX_CANTCREAT
        Error::VenvRemove(_) => 73,     // EX_CANTCREAT
        Error::UvUnavailable(_) => 69,  // EX_UNAVAILABLE — a fetch failed
        Error::PipInstall(_) => 69,     // EX_UNAVAILABLE
        Error::Network(_) => 69,        // EX_UNAVAILABLE
        Error::Manifest(_) => 66,       // EX_NOINPUT
        Error::SelfUpdate(_) => 1,
        Error::Exec(_) => 126,              // Command found but not executable
        Error::TrustViolation { .. } => 77, // EX_NOPERM
        Error::BundleVerify { .. } => 77,   // EX_NOPERM
        // Deliberate user decline — distinct from install/network failures
        // (69) so scripts can branch on "user declined" vs "install broke".
        Error::ConsentDeclined => 70, // EX_SOFTWARE-adjacent slot, reserved here for user-decline
        // The environment, not the launcher, is misconfigured (#53).
        Error::LocalCliUnavailable { .. } => 78, // EX_CONFIG
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `rm -rf ~/.huitzo/venv` hint (#B3) was the wrong remedy for every
    /// cause that actually produced it. No message on the first-run path may
    /// suggest it again.
    fn assert_no_stale_remedy(msg: &str) {
        assert!(
            !msg.contains("rm -rf"),
            "message still suggests deleting the venv:\n{msg}"
        );
        assert!(
            !msg.contains("apt install"),
            "message still tells the user to install a system Python:\n{msg}"
        );
    }

    #[test]
    fn venv_failure_names_uv_and_the_interpreter_not_a_missing_distro_package() {
        let msg = Error::VenvCreate {
            interpreter: "/usr/bin/python3.12".to_string(),
            detail: "error: Failed to create virtualenv\n  Caused by: no space left on device"
                .to_string(),
        }
        .to_string();
        assert!(msg.contains("/usr/bin/python3.12"), "{msg}");
        assert!(msg.contains("uv venv"), "{msg}");
        assert!(msg.contains("no space left on device"), "{msg}");
        // The #B3 misdiagnosis, inverted: the message must actively say that a
        // distro venv package is NOT the missing piece.
        assert!(msg.contains("ensurepip"), "{msg}");
        assert_no_stale_remedy(&msg);
    }

    #[test]
    fn no_python_blames_the_failed_download_not_the_absent_system_python() {
        let msg = Error::NoPython {
            searched: vec!["/usr/bin/python3.9 — Python 3.9, via PATH".to_string()],
            provision: Some(
                "error: Request failed after 3 retries: connection refused".to_string(),
            ),
        }
        .to_string();
        assert!(msg.contains("uv python install"), "{msg}");
        assert!(msg.contains(PROVISIONED_PYTHON), "{msg}");
        assert!(msg.contains("connection refused"), "{msg}");
        assert!(msg.contains("/usr/bin/python3.9"), "{msg}");
        assert_no_stale_remedy(&msg);
    }

    #[test]
    fn uv_failure_names_uv_as_the_cause() {
        let msg =
            Error::UvUnavailable("checksum mismatch on the uv archive".to_string()).to_string();
        assert!(msg.contains("uv"), "{msg}");
        assert!(msg.contains("checksum mismatch on the uv archive"), "{msg}");
        assert_no_stale_remedy(&msg);
        // uv is a fetch dependency, so it exit-codes as unavailable (69), not
        // as a config error the user is expected to fix by hand.
        assert_eq!(
            exit_code(&Error::UvUnavailable(String::new())),
            69,
            "EX_UNAVAILABLE"
        );
    }

    #[test]
    fn subprocess_output_is_indented_and_empty_output_is_labelled() {
        assert_eq!(indent("a\nb\n"), "    a\n    b");
        assert_eq!(indent("   \n"), "    (no output)");
    }
}
