// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use std::fmt;

/// Launcher error types with user-facing messages.
pub enum Error {
    /// No Python 3.11+ found on PATH.
    NoPython,
    /// Virtual environment creation failed.
    VenvCreate(String),
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
            Error::NoPython => write!(
                f,
                "Python 3.11+ required but not found.\n\
                 Searched: python3.14, python3.13, python3.12, python3.11, python3, python\n\n\
                 Install Python:\n\
                 \x20 macOS:  brew install python@3.13\n\
                 \x20 Ubuntu: sudo apt install python3.13\n\
                 \x20 Windows: winget install Python.Python.3.13"
            ),
            Error::VenvCreate(detail) => write!(
                f,
                "Failed to create virtual environment.\n{detail}\n\n\
                 Try: rm -rf ~/.huitzo/venv && huitzo"
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
        Error::NoPython => 78,      // EX_CONFIG
        Error::VenvCreate(_) => 73, // EX_CANTCREAT
        Error::PipInstall(_) => 69, // EX_UNAVAILABLE
        Error::Network(_) => 69,    // EX_UNAVAILABLE
        Error::Manifest(_) => 66,   // EX_NOINPUT
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
