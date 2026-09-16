// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use std::fmt;

use crate::download::{SUPPORTED_KEYS, UnsupportedReason};
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

/// Why the CLI release feed could not be read.
///
/// The launcher calls `api.github.com` unauthenticated, where the allowance is
/// 60 requests/hour per IP — routine to exhaust behind a corporate NAT or on a
/// shared CI runner. Naming that cause separately from "the network is down"
/// and from "the feed returned nonsense" is the whole point of this type (M11).
pub enum FeedError {
    /// 403/429. `remaining` is GitHub's `x-ratelimit-remaining` when present —
    /// `Some(0)` makes the rate limit a fact rather than an inference.
    Forbidden {
        status: u16,
        remaining: Option<u64>,
        retry_after: Option<String>,
    },
    /// Any other non-200 status from the feed host.
    Status(u16),
    /// The request never completed: DNS, TCP, proxy, or timeout.
    Unreachable(String),
    /// The TLS handshake itself failed (m15).
    ///
    /// Split out of [`FeedError::Unreachable`] because it is the one network
    /// failure the user can usually fix themselves and the only one whose
    /// remedy is a setting rather than a wait: the launcher trusts the CA list
    /// compiled into it, not the machine's store, so a TLS-intercepting
    /// corporate proxy fails here until `HUITZO_CA_BUNDLE` names its root.
    /// `detail` carries the proxy/CA settings that were in effect, captured at
    /// construction — reading them again at render time would report the
    /// environment of whoever prints the error, not of the request that failed.
    Tls(String),
    /// The feed answered, but not with something the launcher can parse.
    Malformed(String),
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
    /// The CLI release feed could not be read (M11).
    ///
    /// Distinct from [`Error::NoWheel`]: there the launcher knows exactly what
    /// the feed offers and knows this host is not in it; here it knows nothing
    /// at all. Collapsing the two is what let a routine GitHub rate-limit 403
    /// install the PyPI stub on a perfectly good host.
    FeedUnavailable { url: String, cause: FeedError },
    /// This host is not one Huitzo builds for at all (B5, B9, M3, m11).
    ///
    /// Distinct from [`Error::NoWheel`], which is "the feed was read and this
    /// combination is missing from it": here the answer is known before any
    /// network call, so the refusal happens before consent, before `uv` is
    /// staged and before a venv exists. Nothing is installed on this path.
    UnsupportedPlatform {
        os: String,
        arch: String,
        reason: UnsupportedReason,
    },
    /// The feed was read and carries no wheel this interpreter can install (B4).
    ///
    /// Terminal: the CLI ships only as a compiled wheel, so there is nothing
    /// else to try (D5 — the PyPI fallback is gone, not flag-gated).
    ///
    /// Since T14 this is no longer something the user can fix by installing a
    /// Python. `create_managed_venv` provisions a wheel-compatible CPython
    /// whenever the host has none, so on the bootstrap path this error now only
    /// means the feed does not serve the version the launcher would provision
    /// either — a launcher/feed drift, not a missing system interpreter. The
    /// message must not send the reader off to install one.
    NoWheel {
        platform: String,
        /// The interpreter the wheel was being chosen for, when one is known.
        ///
        /// `None` is a real state, not a placeholder: `--update` parses this
        /// out of the local manifest and a corrupt `python_version` there
        /// leaves the launcher with no interpreter to name (R61). It used to
        /// be flattened to `(0, 0)` and rendered as "Python 0.0", which is a
        /// version that has never existed — the message said something false
        /// about the user's machine.
        python_version: Option<(u8, u8)>,
        feed_version: String,
        available: Vec<String>,
    },
    /// The release feed requires a newer launcher than the one running (M10).
    ///
    /// Distinct from [`Error::NoWheel`]: the feed does carry a wheel for this
    /// host, but the launcher is too old to be trusted to install and run it.
    /// The remedy is an upgrade, and `remedy` names the one that fits how this
    /// launcher was installed.
    LauncherTooOld {
        launcher: String,
        required: String,
        feed_version: String,
        remedy: String,
    },
    /// A wheel installed cleanly but the environment still cannot run the CLI (M8).
    InstallVerify {
        wheel: String,
        python: String,
        detail: String,
    },
    /// HTTP request failed (PyPI, GitHub).
    Network(String),
    /// A proxy environment variable is set to something unusable (m15).
    ///
    /// Terminal for the same reason as [`Error::CaBundle`]: the alternative is
    /// connecting direct, which on a machine where the proxy is the only route
    /// out fails later and somewhere less obvious — and on a machine where it
    /// is not, quietly bypasses the egress path the admin configured.
    ProxyConfig { var: String, value: String },
    /// `HUITZO_CA_BUNDLE` is set but does not yield usable trust anchors (m15).
    ///
    /// Terminal rather than a fall back to the bundled roots: a user who
    /// pointed the launcher at a CA file did so because the bundled roots do
    /// not work here, so silently ignoring the file would turn a typo into the
    /// TLS failure they were trying to fix.
    CaBundle { path: String, detail: String },
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
            Error::FeedUnavailable { url, cause } => write!(
                f,
                "Could not read the Huitzo CLI release feed, so nothing was installed.\n\n\
                 \x20 Feed: {url}\n\
                 \x20 Cause: {cause}\n\n\
                 The CLI is distributed only as a checksum-verified wheel from this feed;\n\
                 there is no package-index fallback, so the launcher cannot guess its way\n\
                 past an unreadable feed. Your environment is untouched — retry when the\n\
                 feed is reachable."
            ),
            Error::UnsupportedPlatform { os, arch, reason } => {
                // One wording, shared with `install.sh`'s `detect_platform`:
                // D2 and D8 are one decision each and must not be stated twice
                // in two voices.
                let (headline, detected, required, why) = match reason {
                    UnsupportedReason::IntelMac => (
                        "Huitzo does not support Intel macOS.",
                        "macOS on x86_64 (Intel)".to_string(),
                        "Apple Silicon (arm64 \u{2014} M-series)".to_string(),
                        "The Huitzo CLI ships only as a compiled wheel and no macos-x86_64 wheel\n\
                         is published at any Python version, so there is nothing that could be\n\
                         installed here. Run Huitzo on an Apple Silicon Mac."
                            .to_string(),
                    ),
                    UnsupportedReason::Musl => (
                        "Huitzo does not support musl-based Linux (Alpine).",
                        format!("Linux on {arch} with musl libc"),
                        "glibc".to_string(),
                        "The Huitzo CLI ships only as a compiled wheel and the release feed\n\
                         publishes manylinux wheels only \u{2014} there is no musllinux build, so\n\
                         pip on a musl host has nothing it can install.\n\n\
                         Use a glibc base image instead (for example `debian-slim` or `ubuntu`),\n\
                         or, on Windows, WSL2 with Ubuntu."
                            .to_string(),
                    ),
                    UnsupportedReason::WindowsArm => (
                        "Huitzo does not support Windows on ARM.",
                        "Windows on aarch64".to_string(),
                        "Windows on x86_64".to_string(),
                        "No launcher binary and no pinned uv build is published for this\n\
                         architecture, so the bootstrap cannot stage itself. x86 emulation is\n\
                         not supported either: the launcher would still find no wheel for the\n\
                         host."
                            .to_string(),
                    ),
                    UnsupportedReason::Unknown => (
                        "Huitzo does not support this platform.",
                        format!("{os} on {arch}"),
                        SUPPORTED_KEYS.to_string(),
                        "The launcher refuses rather than guessing a platform key: asking the\n\
                         release feed for someone else's wheel would install something this\n\
                         machine cannot run."
                            .to_string(),
                    ),
                };
                write!(
                    f,
                    "{headline}\n\n\
                     \x20 Detected: {detected}\n\
                     \x20 Required: {required}\n\n\
                     {why}\n\n\
                     Nothing was installed. See\n\
                     https://github.com/Huitzo-Inc/huitzo-launcher/blob/main/docs/SUPPORT_MATRIX.md"
                )
            }
            Error::NoWheel {
                platform,
                python_version,
                feed_version,
                available,
            } => {
                let interpreter = match python_version {
                    Some((major, minor)) => format!("Python {major}.{minor}"),
                    None => "unknown (the local manifest does not record a usable one)".to_string(),
                };
                // The subset that would work here if the user had that
                // interpreter — the difference between "unsupported machine"
                // and "wrong Python", which is the actionable part.
                let prefix = format!("{platform}-cp");
                let other_pythons: Vec<String> = available
                    .iter()
                    .filter_map(|k| k.strip_prefix(&prefix))
                    .filter_map(|abi| {
                        // `split_at_checked`, not `split_at`: a feed key of
                        // exactly "<platform>-cp" leaves an empty ABI and the
                        // panicking form would crash while rendering an error.
                        let (maj, min) = abi.split_at_checked(1)?;
                        Some(format!("{maj}.{}", min.parse::<u32>().ok()?))
                    })
                    .collect();
                let available = if available.is_empty() {
                    "    (the feed lists no wheels at all)".to_string()
                } else {
                    available
                        .iter()
                        .map(|k| format!("    {k}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                write!(
                    f,
                    "No Huitzo CLI wheel matches this machine, so nothing was installed.\n\n\
                     \x20 Platform key:  {platform}\n\
                     \x20 Interpreter:   {interpreter}\n\
                     \x20 Release:       cli-v{feed_version}\n\
                     \x20 Feed offers:\n{available}\n\n{}\
                     Report a platform you expected to see at\n\
                     https://github.com/Huitzo-Inc/huitzo-launcher/issues",
                    if other_pythons.is_empty() {
                        // No wheel for this platform at ANY Python version.
                        // A *supported* platform in this state means the feed
                        // dropped a build it used to ship; the unsupported
                        // platforms themselves (Intel macOS, musl) never get
                        // here — `Error::UnsupportedPlatform` refuses them
                        // before the feed is even fetched.
                        format!(
                            "The CLI ships as a compiled wheel and there is no {platform} build \
                             at any\nPython version, so no interpreter on this machine can run it.\n\n"
                        )
                    } else {
                        format!(
                            "The feed does have {platform} wheels — for Python {}.\n\
                             Installing one of those by hand is not the fix: the launcher supplies\n\
                             its own CPython {PROVISIONED_PYTHON} whenever no interpreter on the host\n\
                             can take a wheel. So either this feed dropped the build this\n\
                             environment was made for, or it no longer publishes the version the\n\
                             launcher is pinned to. Try `huitzo --launcher-update` first.\n\n",
                            other_pythons.join(", ")
                        )
                    }
                )
            }
            Error::InstallVerify {
                wheel,
                python,
                detail,
            } => write!(
                f,
                "The CLI installed but the environment cannot run it.\n\n\
                 \x20 Wheel:       {wheel}\n\
                 \x20 Interpreter: {python}\n\
                 \x20 `python -P -m huitzo_cli` would fail with:\n{}\n\n\
                 The launcher checks this before reporting success, so you are seeing the\n\
                 real failure instead of a \"success\" line followed by a broken CLI. The\n\
                 environment is left in place for inspection. Please report the wheel name\n\
                 and the output above at\n\
                 https://github.com/Huitzo-Inc/huitzo-launcher/issues",
                indent(detail)
            ),
            Error::LauncherTooOld {
                launcher,
                required,
                feed_version,
                remedy,
            } => write!(
                f,
                "This launcher is too old for the current huitzo release.\n\n\
                 \x20 Launcher:       {launcher}\n\
                 \x20 Required:       {required} or newer\n\
                 \x20 huitzo release: {feed_version}\n\n\
                 Update the launcher, then run huitzo again:\n\
                 \x20 {remedy}"
            ),
            Error::Network(detail) => write!(f, "Network error: {detail}"),
            Error::ProxyConfig { var, value } => write!(
                f,
                "{var} is set to a value the launcher cannot use as a proxy.\n\n\
                 \x20 {var}={value}\n\n\
                 Expected `host:port`, or a full URL such as `http://proxy.corp:8080`\n\
                 (`https://`, `socks5://` and `user:password@` are all accepted). The\n\
                 launcher refuses rather than connecting direct, which would silently\n\
                 bypass the proxy your network requires. Nothing was installed."
            ),
            Error::CaBundle { path, detail } => write!(
                f,
                "HUITZO_CA_BUNDLE is set but no certificate could be loaded from it.\n\n\
                 \x20 Path:   {path}\n\
                 \x20 Detail: {detail}\n\n\
                 The file must be PEM (-----BEGIN CERTIFICATE-----), and may hold a chain.\n\
                 A DER/`.crt` binary file, or a private key on its own, will not do.\n\
                 Nothing was installed."
            ),
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

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeedError::Forbidden {
                status,
                remaining,
                retry_after,
            } => {
                // `x-ratelimit-remaining: 0` turns the diagnosis from a guess
                // into a fact; without the header a 403 is still overwhelmingly
                // the unauthenticated allowance, so say so as a likelihood.
                let cause = if *remaining == Some(0) {
                    "the GitHub API rate limit for this IP is exhausted"
                } else {
                    "HTTP 403/429 — on api.github.com this is almost always the rate limit"
                };
                write!(f, "HTTP {status}: {cause}.")?;
                if let Some(when) = retry_after {
                    write!(f, " Allowance resets {when}.")?;
                }
                write!(
                    f,
                    "\n    Unauthenticated callers get 60 requests/hour per IP address, which a\n\
                     \x20   shared office NAT or a busy CI runner can spend without you. Retry\n\
                     \x20   later, or raise the allowance by exporting a token (no scopes needed,\n\
                     \x20   public data only):\n\
                     \x20     export GITHUB_TOKEN=ghp_…"
                )
            }
            FeedError::Status(status) => write!(
                f,
                "HTTP {status} from the release feed — the server answered, but not with a\n\
                 \x20   release list."
            ),
            FeedError::Unreachable(detail) => write!(
                f,
                "the request never completed: {detail}\n\
                 \x20   A network, DNS or proxy problem rather than anything about your\n\
                 \x20   machine's Python."
            ),
            FeedError::Tls(detail) => write!(f, "the TLS handshake failed: {detail}"),
            FeedError::Malformed(detail) => write!(
                f,
                "the feed was unreadable: {detail}\n\
                 \x20   Something answered on this URL that is not a Huitzo release feed."
            ),
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
        // NOT 73: failing to *remove* the old environment is not failing to
        // create a new one. The remedies differ (ownership/permissions on an
        // existing tree vs. an interpreter or disk problem), so a wrapper that
        // branches on the exit code has to be able to tell them apart.
        Error::VenvRemove(_) => 74,    // EX_IOERR
        Error::UvUnavailable(_) => 69, // EX_UNAVAILABLE — a fetch failed
        Error::PipInstall(_) => 69,    // EX_UNAVAILABLE
        // An infrastructure outage, not a misconfigured host (M11).
        Error::FeedUnavailable { .. } => 69, // EX_UNAVAILABLE
        // This machine/interpreter is not one the feed builds for (B4/B5) —
        // a configuration fact the user can act on, distinct from a 69 outage
        // that is worth retrying verbatim.
        Error::NoWheel { .. } => 78, // EX_CONFIG
        // Same family as NoWheel and for the same reason: the machine is the
        // fact. A wrapper script must not retry this the way it retries a 69.
        Error::UnsupportedPlatform { .. } => 78, // EX_CONFIG
        // The host is fine, the launcher is stale: the user fixes it by
        // upgrading, exactly like NoWheel is fixed by changing platform (M10).
        Error::LauncherTooOld { .. } => 78, // EX_CONFIG
        // Install succeeded, artefact is wrong: bad data from the feed (M8).
        Error::InstallVerify { .. } => 65, // EX_DATAERR
        Error::Network(_) => 69,           // EX_UNAVAILABLE
        // The host is fine and the network may be too; the launcher was handed
        // a CA file it cannot read. That is configuration, like NoWheel.
        Error::CaBundle { .. } => 78,    // EX_CONFIG
        Error::ProxyConfig { .. } => 78, // EX_CONFIG
        Error::Manifest(_) => 66,        // EX_NOINPUT
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

    /// The three new install-path failures must be distinguishable by exit
    /// code alone: a script retrying a 69 outage must not retry an 78
    /// unsupported platform forever, and neither is a 65 bad artefact.
    #[test]
    fn the_install_failure_modes_have_distinct_exit_codes() {
        let feed = Error::FeedUnavailable {
            url: "https://api.github.com/x".to_string(),
            cause: FeedError::Status(503),
        };
        let no_wheel = Error::NoWheel {
            platform: "linux-x86_64".to_string(),
            python_version: Some((3, 11)),
            feed_version: "0.11.1".to_string(),
            available: vec!["linux-x86_64-cp312".to_string()],
        };
        let broken = Error::InstallVerify {
            wheel: "w.whl".to_string(),
            python: "/venv/python".to_string(),
            detail: "boom".to_string(),
        };
        assert_eq!(exit_code(&feed), 69, "EX_UNAVAILABLE — retryable outage");
        assert_eq!(
            exit_code(&no_wheel),
            78,
            "EX_CONFIG — this host, not a blip"
        );
        assert_eq!(exit_code(&broken), 65, "EX_DATAERR — the artefact is wrong");
        for e in [&feed, &no_wheel, &broken] {
            let msg = e.to_string();
            assert_no_stale_remedy(&msg);
            // #B4 is closed: no install-path message may point at a package index.
            assert!(!msg.contains("PyPI"), "{msg}");
            assert!(!msg.contains("pip install"), "{msg}");
        }
    }

    /// Creating the managed venv and removing it are different failures with
    /// different remedies, so they must not share one exit code (R60). They did
    /// — both were 73 — which made "your old venv is root-owned" indexed by
    /// wrapper scripts as "uv venv could not build an environment".
    #[test]
    fn venv_create_and_venv_remove_do_not_share_an_exit_code() {
        let create = Error::VenvCreate {
            interpreter: "/usr/bin/python3.12".to_string(),
            detail: "no space left on device".to_string(),
        };
        let remove = Error::VenvRemove("/home/u/.huitzo/venv: Permission denied".to_string());

        assert_eq!(exit_code(&create), 73, "EX_CANTCREAT — could not build it");
        assert_eq!(exit_code(&remove), 74, "EX_IOERR — could not unlink it");
        assert_ne!(exit_code(&create), exit_code(&remove));

        // And each message still points at its own remedy.
        assert!(create.to_string().contains("uv venv"), "{create}");
        let remove_msg = remove.to_string();
        assert!(remove_msg.contains("permissions"), "{remove_msg}");
        assert!(remove_msg.contains("HUITZO_HOME"), "{remove_msg}");
    }

    #[test]
    fn subprocess_output_is_indented_and_empty_output_is_labelled() {
        assert_eq!(indent("a\nb\n"), "    a\n    b");
        assert_eq!(indent("   \n"), "    (no output)");
    }
}
