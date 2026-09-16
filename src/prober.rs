// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! In-launcher capability prober.
//!
//! Detects the local prerequisites a Huitzo Studio runner needs — the
//! `huitzo` CLI itself, the AI-tool binary (Claude Code's `claude`), and
//! `git` — reporting presence, resolved path, and version for each, plus
//! the host OS/shell support classification.
//!
//! This is the launcher-side half of the "capability prober inside the
//! launcher" design: the prober ships in the one binary the user installs
//! first, which resolves the chicken-and-egg where a CLI-resident prober
//! could not run until the CLI was already installed (roadmap S55).
//!
//! The emitted [`CapabilityReport`] is a stable JSON shape. S56 wires the
//! Hub onboarding rail (`InstallRail` / `hz-rail`) to this exact shape; S55
//! owns only the launcher-side production of the report — it does NOT wire
//! any Hub UI.
//!
//! Roadmap: docs/roadmaps/huitzo-studio.md row S55
//!          (`feat/launcher-one-command-bootstrap`).
//! See also: docs/architecture/huitzo-studio.md §8.2 (the four-phase
//!           journey: Onboard → detect+install CLI tools via hz-rail).
//!
//! NOTE: the launcher repo ships no `Implements:`-style traceability
//! convention or check script; this header comment is the convention this
//! PR introduces for new launcher-side Studio modules.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::errors::Error;

/// Schema version for the emitted [`CapabilityReport`]. Bumped only on a
/// breaking shape change so S56's Hub consumer can negotiate.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// One probed prerequisite tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolProbe {
    /// Stable identifier the Hub rail keys on (`huitzo`, `claude`, `git`).
    pub id: String,
    /// Human-facing display name (`Huitzo CLI`, `Claude Code`, `Git`).
    pub display_name: String,
    /// Whether the binary was resolved — on `PATH`, or (for `huitzo`) in the
    /// launcher-managed `<huitzo_home>/bin`.
    pub present: bool,
    /// Resolved absolute path, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Detected version string, if it could be parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether this tool is required for a functioning runner. A missing
    /// required tool is a "gap" the onboarding rail must close before the
    /// runner can pair.
    pub required: bool,
    /// Copy-paste install hint surfaced when the tool is absent. Free-form,
    /// per-OS; the Hub may override with its signed manifest (S57).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_hint: Option<String>,
}

/// Support classification of the host environment per the published
/// OS/shell matrix (see docs/SUPPORT_MATRIX.md).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Officially supported: macOS, Linux, or WSL on a non-admin-locked box.
    Supported,
    /// Runs but outside the officially-supported matrix (best effort).
    Unsupported,
}

/// Host environment classification surfaced alongside the tool probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostInfo {
    /// `macos`, `linux`, `windows`.
    pub os: String,
    /// `aarch64`, `x86_64`, or the raw arch string.
    pub arch: String,
    /// Best-effort current shell basename (`zsh`, `bash`, `fish`, `pwsh`…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// True when running inside the Windows Subsystem for Linux.
    pub wsl: bool,
    /// Official support classification.
    pub support: SupportLevel,
    /// Human-facing rationale when `support == Unsupported`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
}

/// The full capability report — the wire shape S56's Hub onboarding rail
/// consumes. Serialized as JSON when the user runs `huitzo --launcher-detect`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityReport {
    pub schema_version: u32,
    pub launcher_version: String,
    pub host: HostInfo,
    pub tools: Vec<ToolProbe>,
}

impl CapabilityReport {
    /// True when every `required` tool is present. The runner cannot pair
    /// while a required gap is open.
    pub fn ready(&self) -> bool {
        self.tools.iter().filter(|t| t.required).all(|t| t.present)
    }

    /// The ids of required tools that are missing — the gaps the onboarding
    /// rail must walk the user through closing.
    pub fn missing_required(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter(|t| t.required && !t.present)
            .map(|t| t.id.clone())
            .collect()
    }
}

/// Probe the local environment and assemble the [`CapabilityReport`].
///
/// Read-only: no install, no network. Each third-party tool is asked for its
/// `--version`; a `huitzo` that turns out to be the launcher is deliberately
/// not (see [`probe_huitzo`]), because answering that question would mean
/// bootstrapping the managed venv. Never logs secrets — only tool ids, paths,
/// and version strings are recorded.
pub fn probe() -> CapabilityReport {
    let host = probe_host();
    let tools = vec![
        probe_huitzo(),
        probe_tool(
            "claude",
            "Claude Code",
            &["claude"],
            &["--version"],
            true,
            Some("npm install -g @anthropic-ai/claude-code"),
        ),
        probe_tool(
            "git",
            "Git",
            &["git"],
            &["--version"],
            true,
            git_install_hint(&host.os),
        ),
    ];

    CapabilityReport {
        schema_version: REPORT_SCHEMA_VERSION,
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
        tools,
    }
}

/// The copy-paste remediation for a machine with no Huitzo CLI at all.
const HUITZO_INSTALL_HINT: &str =
    "curl -sSf https://raw.githubusercontent.com/Huitzo-Inc/huitzo-launcher/main/install.sh | sh";

/// The launcher-managed `huitzo` binary: `<huitzo_home>/bin/huitzo`, or `None`
/// on a host where `$HUITZO_HOME` has no value and no home directory to default
/// to.
///
/// Every `dirs::` helper resolves through the home directory and *panics* when
/// there is none. Everywhere else in the launcher that is fine — nothing can be
/// installed without a home anyway — but the prober is precisely the thing you
/// run to find out what is wrong with a machine, so it degrades to "no managed
/// install" instead of aborting the report.
fn managed_launcher() -> Option<PathBuf> {
    if std::env::var_os("HUITZO_HOME").is_none() && dirs::home_dir().is_none() {
        return None;
    }
    let name = if cfg!(windows) {
        "huitzo.exe"
    } else {
        "huitzo"
    };
    Some(crate::dirs::bin_dir().join(name))
}

/// Probe the Huitzo CLI itself.
///
/// Two deliberate departures from [`probe_tool`], both needed for the report to
/// be true — at the moment `install.sh` asks for it (M2), and afterwards:
///
/// * **`PATH` decides; the managed binary is the fallback.** Typing `huitzo`
///   runs whatever `PATH` resolves first, so that is what the report names. A
///   stale pip/pipx `huitzo` ahead of `<huitzo_home>/bin` shadows the managed
///   install, and naming the managed one there would report a launcher that is
///   not the one that runs — the report would be wrong about the only thing it
///   exists to answer. `PATH` having no `huitzo` at all is the M2 case: the
///   installer writes the launcher to `<huitzo_home>/bin` and appends that
///   directory to a shell *profile*, so the `PATH` of the shell running the
///   installer is still the stale pre-install one. That is why the one-command
///   bootstrap used to end on `[--] Huitzo CLI` / `Missing required tools:
///   huitzo`, declaring the tool it had just installed missing; the managed
///   binary answers there. `which` is still what answers "is this an executable
///   file", so a `$HUITZO_HOME/bin` that holds nothing runnable is still
///   reported missing.
/// * **A launcher is never asked for `--version`.** That flag is answered by
///   the *Python* CLI, so reaching it means the launcher bootstraps the managed
///   venv first — downloading `uv`, a CPython and a wheel. A prober documented
///   as read-only must not install anything, least of all from inside the
///   installer's own closing status line. So a resolved `huitzo` that turns out
///   to be a launcher has its CLI version read out of the manifest the
///   bootstrap writes, and simply has none until a bootstrap has happened.
fn probe_huitzo() -> ToolProbe {
    let resolved = which::which("huitzo")
        .ok()
        .or_else(|| managed_launcher().and_then(|m| which::which(m).ok()));

    let version = resolved.as_deref().and_then(huitzo_version);

    let present = resolved.is_some();
    ToolProbe {
        id: "huitzo".to_string(),
        display_name: "Huitzo CLI".to_string(),
        present,
        path: resolved.map(|p| p.to_string_lossy().to_string()),
        version,
        required: true,
        install_hint: (!present).then(|| HUITZO_INSTALL_HINT.to_string()),
    }
}

/// The CLI version to report for a resolved `huitzo`, costing nothing.
///
/// Which binary it is decides where the answer comes from, because only one of
/// the two can be asked directly:
///
/// * a **launcher** (the managed one, or a Homebrew/cargo/dev copy on `PATH`
///   pointing at the same `$HUITZO_HOME`) would have to bootstrap the managed
///   venv to answer `--version`, so the manifest answers instead;
/// * a **pip/pipx `huitzo`** is the Python CLI itself, which answers
///   `--version` for free.
fn huitzo_version(bin: &Path) -> Option<String> {
    if is_launcher(bin) {
        installed_cli_version()
    } else {
        probe_version(bin, &["--version"])
    }
}

/// Is this binary the launcher rather than the Python CLI?
///
/// `--launcher-version` is the discriminator because the launcher intercepts it
/// before consent, bootstrap, update check or any network call — it prints one
/// line and returns — while the Python CLI does not have the flag at all. The
/// output is matched, not just the exit status, so a CLI that shrugs off an
/// unknown flag with exit 0 is not mistaken for a launcher.
fn is_launcher(bin: &Path) -> bool {
    Command::new(bin)
        .arg("--launcher-version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .trim_start()
                    .starts_with("huitzo-launcher")
        })
}

/// The CLI version the managed environment actually has, per the manifest the
/// bootstrap writes.
///
/// Read with a narrow local shape rather than through `manifest::load()`: that
/// loader migrates old schemas and deletes corrupt ones, i.e. it *writes*. The
/// prober must be able to run against someone's real `$HUITZO_HOME` — including
/// from a test — without editing it.
fn installed_cli_version() -> Option<String> {
    #[derive(Deserialize)]
    struct InstalledCli {
        huitzo_version: String,
    }

    // Same home-directory caveat as `managed_launcher`: no home, no manifest,
    // and no panic on the way to finding that out.
    managed_launcher()?;
    let raw = std::fs::read_to_string(crate::dirs::manifest_path()).ok()?;
    let parsed: InstalledCli = serde_json::from_str(&raw).ok()?;
    let version = strip_control(&parsed.huitzo_version).trim().to_string();
    (!version.is_empty()).then_some(version)
}

/// Resolve a single tool on `PATH` and probe its version.
///
/// `candidates` is tried in order via `which`; the first hit wins. The
/// version is parsed from the first line of `<bin> <version_args>` stdout.
fn probe_tool(
    id: &str,
    display_name: &str,
    candidates: &[&str],
    version_args: &[&str],
    required: bool,
    install_hint: Option<&str>,
) -> ToolProbe {
    let resolved = candidates.iter().find_map(|c| which::which(c).ok());

    let (present, path, version) = match resolved {
        Some(p) => {
            let version = probe_version(&p, version_args);
            (true, Some(p.to_string_lossy().to_string()), version)
        }
        None => (false, None, None),
    };

    ToolProbe {
        id: id.to_string(),
        display_name: display_name.to_string(),
        present,
        path,
        version,
        required,
        // Only surface an install hint when the tool is actually missing —
        // a present tool needs no remediation.
        install_hint: if present {
            None
        } else {
            install_hint.map(str::to_string)
        },
    }
}

/// Run `<bin> <args>` and extract a version from stdout via
/// [`parse_version_token`]. Read-only; never fails the probe — a tool that
/// won't report a version is still "present".
fn probe_version(bin: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(bin)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_version_token(&text)
}

/// Extract a version-looking token from a tool's `--version` stdout.
///
/// The report is a machine contract, so a version field must hold a version and
/// nothing else. Two things had to be taken out of it (M5):
///
/// * **Terminal control codes.** The CLI colourises its own version banner and
///   does not know it is talking to a pipe, so `huitzo --version` emitted
///   `huitzo-cli \x1b[1;36m0.11\x1b[0m.\x1b[1;36m1\x1b[0m`. Every escape is
///   stripped *before* tokenising — which also un-hides the version, since the
///   escape-prefixed token no longer starts with a digit and the whole line was
///   being handed back as a fallback.
/// * **The tool-name prefix.** `claude` and `git` came back as bare `2.1.273` /
///   `2.42.0` while `huitzo` came back with its name glued on. One shape.
///
/// Returns the first whitespace token on the first non-empty line that is a
/// version: an ASCII digit, or a `v`/`V` tag prefix followed by one (the `v` is
/// dropped). Falls back to the cleaned first line when a tool reports something
/// with no version in it at all; returns `None` only when there is no non-empty
/// line. Pure + side-effect-free so it is unit-testable without spawning a
/// process.
fn parse_version_token(stdout: &str) -> Option<String> {
    let cleaned = strip_control(stdout);
    let first_line = cleaned.lines().find(|l| !l.trim().is_empty())?.trim();

    let token = first_line.split_whitespace().find_map(version_token);

    Some(token.unwrap_or_else(|| first_line.to_string()))
}

/// A single whitespace token, if it reads as a version number.
fn version_token(token: &str) -> Option<String> {
    // `v1.2.3` is a common shape; `version` (as in `git version 2.43.0`) is
    // not, and is rejected by the digit check that follows the strip.
    let candidate = token.strip_prefix(['v', 'V']).unwrap_or(token);
    candidate
        .starts_with(|c: char| c.is_ascii_digit())
        .then(|| candidate.to_string())
}

/// Remove ANSI escape sequences and every remaining control character (bar
/// newline) from a tool's output.
///
/// Newlines survive because the caller still splits the output into lines;
/// everything else — CSI colour runs, OSC title sequences, a stray `\r` from a
/// Windows tool — is dropped, so no control byte can reach the JSON payload
/// whichever branch of [`parse_version_token`] ends up producing the value.
fn strip_control(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            if c == '\n' || !c.is_control() {
                out.push(c);
            }
            continue;
        }
        match chars.next() {
            // CSI — `ESC [` params, ended by a byte in `@`..=`~` (the `m` of a
            // colour run, the `K` of an erase, …).
            Some('[') => {
                for c in chars.by_ref() {
                    if matches!(c, '\u{40}'..='\u{7e}') {
                        break;
                    }
                }
            }
            // OSC — `ESC ]` … ended by BEL or by ST (`ESC \`).
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\u{7}' {
                        break;
                    }
                    if c == '\u{1b}' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            // Any other escape is two characters wide; both are consumed.
            _ => {}
        }
    }

    out
}

/// Classify the host OS / shell / WSL and derive support level.
fn probe_host() -> HostInfo {
    // The same call the bootstrap makes before it downloads anything
    // (`download::ensure_supported_platform`). Reused rather than re-derived:
    // a second opinion about which hosts are supported is exactly how the
    // report came to say `supported` on the hosts the installer refuses.
    let refusal = crate::download::current_platform().err();

    build_host(
        normalized_os(),
        std::env::consts::ARCH.to_string(),
        current_shell(),
        is_wsl(),
        refusal.as_ref(),
    )
}

/// Assemble a [`HostInfo`] from already-gathered facts.
///
/// Split out of [`probe_host`] so every classification — including the ones
/// this machine can never produce, such as Intel macOS — is reachable from a
/// test without a Mac or an Alpine container.
fn build_host(
    os: String,
    arch: String,
    shell: Option<String>,
    wsl: bool,
    platform_refusal: Option<&Error>,
) -> HostInfo {
    let (support, unsupported_reason) = classify_support(&os, wsl, platform_refusal);

    HostInfo {
        os,
        arch,
        shell,
        wsl,
        support,
        unsupported_reason,
    }
}

/// Map `std::env::consts::OS` onto the matrix's short names.
fn normalized_os() -> String {
    match std::env::consts::OS {
        "macos" => "macos".to_string(),
        "linux" => "linux".to_string(),
        "windows" => "windows".to_string(),
        other => other.to_string(),
    }
}

/// Apply the published OS/shell support matrix (docs/SUPPORT_MATRIX.md).
///
/// `platform_refusal` is whatever [`download::current_platform`] refused this
/// host with, and it outranks every rule below. T5 made Intel macOS (D2) and
/// musl/Alpine (D8) hard refusals: the installer exits before it downloads
/// anything on those hosts. The prober went on reporting them `supported`,
/// i.e. the report was optimistic exactly where the installer was correct. The
/// reason string is the installer's own rendered refusal — one wording for one
/// decision, so the two cannot drift apart again.
///
/// Below that: macOS, Linux, and WSL are supported. On native Windows (non-WSL)
/// the CLI installs and runs, but the Studio *runner* requires WSL2 — its
/// outbound daemon and POSIX exec path target a POSIX shell — so native Windows
/// is classified off the runner matrix (`Unsupported`) with a reason that says
/// exactly that. Admin-locked corporate machines are called out in the matrix
/// doc but cannot be reliably auto-detected from the launcher, so they are
/// flagged in docs rather than here.
///
/// The `--launcher-detect` exit code is unaffected: it reports required-tool
/// presence only, as documented in docs/SUPPORT_MATRIX.md.
fn classify_support(
    os: &str,
    wsl: bool,
    platform_refusal: Option<&Error>,
) -> (SupportLevel, Option<String>) {
    if let Some(refusal @ Error::UnsupportedPlatform { .. }) = platform_refusal {
        return (SupportLevel::Unsupported, Some(refusal.to_string()));
    }

    match os {
        "macos" | "linux" => (SupportLevel::Supported, None),
        "windows" if wsl => (SupportLevel::Supported, None),
        "windows" => (
            SupportLevel::Unsupported,
            Some(
                "The Huitzo CLI installs and runs on native Windows. The Studio \
                 runner requires WSL2 (Ubuntu) — install WSL2 and run the bootstrap \
                 there to pair a runner. See docs/SUPPORT_MATRIX.md."
                    .to_string(),
            ),
        ),
        other => (
            SupportLevel::Unsupported,
            Some(format!(
                "{other} is not in the officially-supported OS matrix. \
                 See docs/SUPPORT_MATRIX.md."
            )),
        ),
    }
}

/// Best-effort current shell basename.
///
/// On Unix, derive from `$SHELL`. On Windows, fall back to `$PSModulePath`
/// presence as a weak PowerShell signal, else `cmd`.
fn current_shell() -> Option<String> {
    if let Ok(shell) = std::env::var("SHELL") {
        return std::path::Path::new(&shell)
            .file_name()
            .map(|s| s.to_string_lossy().to_string());
    }
    if cfg!(windows) {
        if std::env::var_os("PSModulePath").is_some() {
            return Some("powershell".to_string());
        }
        return Some("cmd".to_string());
    }
    None
}

/// Detect the Windows Subsystem for Linux.
///
/// On Linux, WSL exposes `WSL_DISTRO_NAME` / `WSL_INTEROP` in the
/// environment and "microsoft" in `/proc/version`. We check the cheap env
/// signals first, then the kernel string.
fn is_wsl() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/version")
        .map(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("microsoft") || v.contains("wsl")
        })
        .unwrap_or(false)
}

/// Per-OS (and, on Linux, per-distro) git install hint for the probe's
/// `install_hint`.
fn git_install_hint(os: &str) -> Option<&'static str> {
    match os {
        "macos" => Some("xcode-select --install   # or: brew install git"),
        "linux" => Some(linux_git_install_hint()),
        _ => Some("https://git-scm.com/downloads"),
    }
}

/// Pick a package-manager-specific git install command for the running
/// Linux distro. Falls back to `apt` when no other package manager is
/// detected, since Debian/Ubuntu derivatives are the common case.
fn linux_git_install_hint() -> &'static str {
    if std::path::Path::new("/etc/alpine-release").exists() {
        return "apk add git";
    }
    if which::which("dnf").is_ok() {
        return "sudo dnf install git";
    }
    if which::which("pacman").is_ok() {
        return "sudo pacman -S git";
    }
    "sudo apt install git   # or your distro's package manager"
}

/// Locate this tool by id in the report, if probed.
impl CapabilityReport {
    /// Used by the lib consumer (S56's Hub-side wiring) and the tests; the
    /// binary path emits the whole report and does not look up by id.
    #[allow(dead_code)]
    pub fn tool(&self, id: &str) -> Option<&ToolProbe> {
        self.tools.iter().find(|t| t.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::UnsupportedReason;

    /// The refusal `download::current_platform()` hands back on a host T5
    /// declared unsupported. Built directly because the resolver reads
    /// compile-time OS/arch constants: this is the only way to exercise the
    /// Intel-macOS and musl branches from a glibc x86_64 Linux runner.
    fn refusal(os: &str, arch: &str, reason: UnsupportedReason) -> Error {
        Error::UnsupportedPlatform {
            os: os.to_string(),
            arch: arch.to_string(),
            reason,
        }
    }

    #[test]
    fn classify_macos_and_linux_supported() {
        assert_eq!(
            classify_support("macos", false, None).0,
            SupportLevel::Supported
        );
        assert_eq!(
            classify_support("linux", false, None).0,
            SupportLevel::Supported
        );
    }

    #[test]
    fn classify_windows_non_wsl_unsupported_with_reason() {
        let (level, reason) = classify_support("windows", false, None);
        assert_eq!(level, SupportLevel::Unsupported);
        let reason = reason.expect("non-WSL Windows must carry a rationale");
        assert!(reason.contains("WSL"));
    }

    #[test]
    fn classify_windows_wsl_supported() {
        assert_eq!(
            classify_support("windows", true, None).0,
            SupportLevel::Supported
        );
    }

    #[test]
    fn parse_version_token_extracts_digit_led_token() {
        // git emits "git version 2.43.0"
        assert_eq!(
            parse_version_token("git version 2.43.0\n").as_deref(),
            Some("2.43.0")
        );
        // claude / huitzo emit a bare "1.2.3" style line
        assert_eq!(parse_version_token("2.1.159").as_deref(), Some("2.1.159"));
        assert_eq!(
            parse_version_token("huitzo 0.5.2\nextra\n").as_deref(),
            Some("0.5.2")
        );
    }

    #[test]
    fn parse_version_token_falls_back_then_none() {
        // No digit-led token anywhere → fall back to the trimmed first line.
        assert_eq!(
            parse_version_token("unknown tool build").as_deref(),
            Some("unknown tool build")
        );
        // No non-empty line → None.
        assert_eq!(parse_version_token(""), None);
        assert_eq!(parse_version_token("   \n"), None);
    }

    #[test]
    fn classify_unknown_os_unsupported() {
        let (level, reason) = classify_support("freebsd", false, None);
        assert_eq!(level, SupportLevel::Unsupported);
        assert!(reason.unwrap().contains("freebsd"));
    }

    #[test]
    fn git_install_hint_is_apt_based_on_a_debian_derivative_ci_runner() {
        // This test runs on the CI/dev image (Debian/Ubuntu derivative, no
        // dnf/pacman/alpine-release), so the fallback branch is exercised.
        assert!(linux_git_install_hint().contains("apt"));
    }

    #[test]
    fn missing_tool_has_install_hint() {
        // A guaranteed-absent binary name probes as missing + carries a hint.
        let probe = probe_tool(
            "definitely-not-a-real-binary-xyz",
            "Nope",
            &["definitely-not-a-real-binary-xyz-zzz"],
            &["--version"],
            true,
            Some("install me"),
        );
        assert!(!probe.present);
        assert_eq!(probe.path, None);
        assert_eq!(probe.version, None);
        assert_eq!(probe.install_hint.as_deref(), Some("install me"));
    }

    #[test]
    fn present_tool_drops_install_hint() {
        // The Rust toolchain ships a `cargo` we can rely on under test.
        let probe = probe_tool(
            "cargo",
            "Cargo",
            &["cargo"],
            &["--version"],
            false,
            Some("install rust"),
        );
        if probe.present {
            assert!(probe.path.is_some());
            assert_eq!(
                probe.install_hint, None,
                "present tools must not carry an install hint"
            );
        }
    }

    #[test]
    fn report_ready_iff_all_required_present() {
        let report = CapabilityReport {
            schema_version: REPORT_SCHEMA_VERSION,
            launcher_version: "0.0.0".to_string(),
            host: HostInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                shell: Some("bash".to_string()),
                wsl: false,
                support: SupportLevel::Supported,
                unsupported_reason: None,
            },
            tools: vec![
                ToolProbe {
                    id: "huitzo".to_string(),
                    display_name: "Huitzo CLI".to_string(),
                    present: true,
                    path: Some("/usr/bin/huitzo".to_string()),
                    version: Some("0.5.2".to_string()),
                    required: true,
                    install_hint: None,
                },
                ToolProbe {
                    id: "git".to_string(),
                    display_name: "Git".to_string(),
                    present: false,
                    path: None,
                    version: None,
                    required: true,
                    install_hint: Some("apt install git".to_string()),
                },
            ],
        };
        assert!(!report.ready());
        assert_eq!(report.missing_required(), vec!["git".to_string()]);
    }

    #[test]
    fn report_serializes_to_stable_json_shape() {
        let report = probe();
        let json = serde_json::to_string(&report).unwrap();
        // Round-trips and keeps the schema-version + host + tools keys.
        let back: CapabilityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(back.tools.len(), 3);
        assert!(back.tool("huitzo").is_some());
        assert!(back.tool("claude").is_some());
        assert!(back.tool("git").is_some());
    }

    #[test]
    fn probe_populates_launcher_version() {
        let report = probe();
        assert_eq!(report.launcher_version, env!("CARGO_PKG_VERSION"));
    }
    #[test]
    fn intel_macos_host_is_unsupported_in_the_installers_own_words() {
        // D2 / T5: the installer refuses here before it downloads anything.
        // The report must not say `supported` where the install path refuses.
        let refusal = refusal("macos", "x86_64", UnsupportedReason::IntelMac);
        let host = build_host(
            "macos".to_string(),
            "x86_64".to_string(),
            Some("zsh".to_string()),
            false,
            Some(&refusal),
        );

        // The shape S56's Hub rail actually reads. Printed so `--nocapture`
        // shows the Intel-Mac host block on a machine that is not one.
        println!("{}", serde_json::to_string_pretty(&host).unwrap());

        assert_eq!(host.support, SupportLevel::Unsupported);
        let reason = host
            .unsupported_reason
            .as_deref()
            .expect("must carry a rationale");
        assert!(reason.contains("Apple Silicon"), "{reason}");
        // One wording for one decision: the report quotes the refusal, it does
        // not paraphrase it into a second, driftable voice.
        assert_eq!(reason, refusal.to_string());
    }

    #[test]
    fn musl_host_is_unsupported_in_the_installers_own_words() {
        // D8 / T5: Alpine and any other musl host. Both arches refuse.
        for arch in ["x86_64", "aarch64"] {
            let refusal = refusal("linux", arch, UnsupportedReason::Musl);
            let host = build_host(
                "linux".to_string(),
                arch.to_string(),
                Some("sh".to_string()),
                false,
                Some(&refusal),
            );

            assert_eq!(host.support, SupportLevel::Unsupported, "{arch}");
            let reason = host.unsupported_reason.expect("must carry a rationale");
            assert!(reason.contains("glibc"), "{reason}");
            assert_eq!(reason, refusal.to_string());
        }
    }

    #[test]
    fn a_platform_refusal_outranks_the_wsl_runner_rule() {
        // Windows-on-ARM has no launcher asset at all (m11). The Windows
        // branch below would otherwise explain WSL2 to someone whose machine
        // cannot run the bootstrap in WSL either.
        let refusal = refusal("windows", "aarch64", UnsupportedReason::WindowsArm);
        let (level, reason) = classify_support("windows", true, Some(&refusal));
        assert_eq!(level, SupportLevel::Unsupported);
        assert!(reason.unwrap().contains("Windows on ARM"));
    }

    #[test]
    fn a_supported_platform_leaves_the_matrix_rules_in_charge() {
        // No refusal → the OS/WSL matrix still decides, unchanged.
        assert_eq!(
            classify_support("linux", false, None).0,
            SupportLevel::Supported
        );
        assert_eq!(
            classify_support("windows", false, None).0,
            SupportLevel::Unsupported
        );
    }

    #[test]
    fn strip_control_removes_csi_osc_and_stray_control_bytes() {
        assert_eq!(strip_control("\u{1b}[1;36m0.11\u{1b}[0m"), "0.11");
        assert_eq!(strip_control("\u{1b}]0;title\u{7}1.2.3"), "1.2.3");
        assert_eq!(strip_control("\u{1b}]0;title\u{1b}\\1.2.3"), "1.2.3");
        // Newlines survive so the caller can still split into lines.
        assert_eq!(strip_control("a\r\nb"), "a\nb");
        assert_eq!(strip_control("1.2.3"), "1.2.3");
    }

    #[test]
    fn parse_version_token_strips_the_cli_colour_banner_and_its_name() {
        // Verbatim shape of `huitzo --version` through a pipe (M5): the CLI
        // colourises regardless of the TTY, and prefixes its own name.
        let raw = "huitzo-cli \u{1b}[1;36m0.11\u{1b}[0m.\u{1b}[1;36m1\u{1b}[0m\n";
        let parsed = parse_version_token(raw).expect("a version");
        assert_eq!(parsed, "0.11.1");
        assert!(!parsed.contains('\u{1b}'));
    }

    #[test]
    fn parse_version_token_never_emits_a_control_character() {
        // Including on the no-version-found fallback branch, which used to be
        // exactly how the escape-laden line reached the payload.
        let cases = [
            "\u{1b}[31mnothing version-shaped here\u{1b}[0m",
            "\u{1b}[1;36mbuild\u{1b}[0m \u{1b}[1;36mtag\u{1b}[0m",
            "tool \u{7}\r1.0.0",
        ];
        for raw in cases {
            let parsed = parse_version_token(raw).expect("a value");
            assert!(
                !parsed.chars().any(char::is_control),
                "control character survived: {parsed:?}"
            );
            assert!(!parsed.contains('\u{1b}'), "{parsed:?}");
        }
    }

    #[test]
    fn parse_version_token_normalises_a_v_prefixed_tag() {
        assert_eq!(
            parse_version_token("mytool v1.2.3").as_deref(),
            Some("1.2.3")
        );
        // `version` must not be mistaken for a `v`-tagged number.
        assert_eq!(
            parse_version_token("git version 2.43.0").as_deref(),
            Some("2.43.0")
        );
    }

    #[test]
    fn huitzo_probe_reports_a_bare_version_and_no_escape_codes() {
        let report = probe();
        let huitzo = report.tool("huitzo").expect("huitzo is always probed");
        if let Some(version) = &huitzo.version {
            assert!(!version.contains("huitzo"), "tool-name prefix: {version:?}");
            assert!(!version.chars().any(char::is_control), "{version:?}");
        }

        // Nothing anywhere in the serialized payload may carry an escape.
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(json.matches('\u{1b}').count(), 0);
        assert_eq!(json.matches("\\u001b").count(), 0);
    }

    /// Replace `PATH` with an empty directory and hand back the old value.
    ///
    /// The fallback tests below are about what happens when `PATH` has no
    /// `huitzo` on it. A dev box usually does have one (a cargo-installed
    /// launcher), so leaving the real `PATH` in place would have them assert
    /// the wrong branch — or pass for the wrong reason.
    fn path_without_huitzo(dir: &Path) -> Option<std::ffi::OsString> {
        let empty = dir.join("empty-path");
        std::fs::create_dir_all(&empty).unwrap();
        let previous = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", &empty) };
        previous
    }

    fn restore_path(previous: Option<std::ffi::OsString>) {
        match previous {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }

    #[cfg(unix)]
    fn write_shim(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_launcher_is_read_from_the_manifest_and_never_asked_for_a_version() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };
        std::fs::create_dir_all(tmp.path().join("bin")).unwrap();
        // Nothing on PATH, so the managed binary is what gets probed.
        let previous_path = path_without_huitzo(tmp.path());

        // A stand-in launcher: answers --launcher-version instantly (as the
        // real one does, before consent/bootstrap/network), and treats
        // --version as the trigger for a full managed-venv bootstrap. Touching
        // the tripwire is the failure the prober must not cause.
        let tripwire = tmp.path().join("bootstrap-ran");
        let managed = managed_launcher().expect("HUITZO_HOME is set");
        write_shim(
            &managed,
            &format!(
                "case \"$1\" in\n  --launcher-version) echo 'huitzo-launcher 0.3.3'; exit 0 ;;\n\
                 esac\ntouch {}\necho 'huitzo-cli 0.11.1'\n",
                tripwire.display()
            ),
        );

        assert!(is_launcher(&managed));

        // No manifest yet: present, but honestly versionless — the bootstrap
        // has not run, and the prober will not run it to find out.
        let probe = probe_huitzo();
        assert!(probe.present);
        assert_eq!(probe.version, None);
        assert!(
            !tripwire.exists(),
            "the prober bootstrapped the managed venv"
        );

        // With a manifest, the version is the CLI the venv actually has.
        std::fs::write(
            crate::dirs::manifest_path(),
            r#"{"schema_version":3,"python_path":"/usr/bin/python3","python_version":"3.13","huitzo_version":"0.11.1","launcher_version":"0.3.3","last_update_check":0,"pending_update":null,"created_at":0}"#,
        )
        .unwrap();
        assert_eq!(probe_huitzo().version.as_deref(), Some("0.11.1"));
        assert!(
            !tripwire.exists(),
            "the prober bootstrapped the managed venv"
        );

        restore_path(previous_path);
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[cfg(unix)]
    #[test]
    fn a_pip_installed_cli_is_asked_directly_and_its_banner_is_cleaned() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        // Not a launcher: no --launcher-version, and --version is the CLI's own
        // colourised banner. It is safe to run, and must still come back bare.
        let shim = tmp.path().join("huitzo");
        write_shim(
            &shim,
            "printf 'huitzo-cli \\033[1;36m0.11\\033[0m.\\033[1;36m1\\033[0m\\n'",
        );

        assert!(!is_launcher(&shim));
        assert_eq!(huitzo_version(&shim).as_deref(), Some("0.11.1"));

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn a_stale_path_falls_back_to_the_managed_launcher() {
        // M2: the shell running `install.sh` has the pre-install PATH, so
        // `huitzo` is not on it. The managed binary answers instead, which is
        // what stops the bootstrap ending on "Missing required tools: huitzo".
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };
        let previous_path = path_without_huitzo(tmp.path());

        // An empty $HUITZO_HOME/bin must NOT be reported as an install: the
        // fix for M2 is "look in the right place", not "assume success".
        std::fs::create_dir_all(tmp.path().join("bin")).unwrap();
        let managed = managed_launcher().expect("HUITZO_HOME is set");
        assert_eq!(
            managed,
            tmp.path().join("bin").join(if cfg!(windows) {
                "huitzo.exe"
            } else {
                "huitzo"
            })
        );
        assert!(which::which(&managed).is_err());
        assert!(
            !probe_huitzo().present,
            "an empty bin dir is not an install"
        );

        // A real executable there resolves, with no PATH entry for it.
        std::fs::write(&managed, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(which::which(&managed).is_ok());
            let probe = probe_huitzo();
            assert!(probe.present, "managed launcher must resolve off PATH");
            assert_eq!(probe.path.as_deref(), managed.to_str());
            assert_eq!(probe.install_hint, None);
        }

        restore_path(previous_path);
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[cfg(unix)]
    #[test]
    fn a_shadowing_path_install_is_reported_over_the_managed_one() {
        // R64: `huitzo` on PATH ahead of $HUITZO_HOME/bin is what the user's
        // shell executes, so it is what the report must name. Reporting the
        // managed launcher here would name a binary that is not the one that
        // runs — and would hand the Hub rail the managed CLI's version for an
        // install the user never invokes.
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };
        std::fs::create_dir_all(tmp.path().join("bin")).unwrap();

        // A complete managed install: the launcher, plus the manifest its
        // bootstrap wrote recording a much newer CLI.
        let managed = managed_launcher().expect("HUITZO_HOME is set");
        write_shim(
            &managed,
            "case \"$1\" in\n  --launcher-version) echo 'huitzo-launcher 0.3.3'; exit 0 ;;\nesac\n",
        );
        std::fs::write(
            crate::dirs::manifest_path(),
            r#"{"schema_version":3,"python_path":"/usr/bin/python3","python_version":"3.13","huitzo_version":"0.11.1","launcher_version":"0.3.3","last_update_check":0,"pending_update":null,"created_at":0}"#,
        )
        .unwrap();

        // And a stale pip/pipx install shadowing it on PATH.
        let pip_dir = tmp.path().join("pip-bin");
        std::fs::create_dir_all(&pip_dir).unwrap();
        let pip_shim = pip_dir.join("huitzo");
        write_shim(
            &pip_shim,
            "case \"$1\" in\n  --launcher-version) exit 1 ;;\n  --version) echo '0.9.0'; exit 0 ;;\nesac\n",
        );

        let previous_path = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", &pip_dir) };

        let probe = probe_huitzo();

        restore_path(previous_path);
        unsafe { std::env::remove_var("HUITZO_HOME") };

        assert!(probe.present);
        assert_eq!(
            probe.path.as_deref(),
            pip_shim.to_str(),
            "the report must name the binary the shell actually runs"
        );
        assert_eq!(
            probe.version.as_deref(),
            Some("0.9.0"),
            "the shadowed managed manifest must not supply the version"
        );
    }

    #[test]
    fn installed_cli_version_reads_the_manifest_without_rewriting_it() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", tmp.path()) };

        // No manifest yet — the bootstrap has not run. No version, and the
        // prober must not execute the launcher to go and find one.
        assert_eq!(installed_cli_version(), None);

        // A v1 manifest: readable here, and left byte-identical on disk (the
        // migrating loader would have rewritten it).
        let raw = r#"{"schema_version":1,"python_path":"/usr/bin/python3","python_version":"3.12","huitzo_version":"0.11.1","launcher_version":"0.3.3","last_update_check":0,"pending_update":null,"created_at":0}"#;
        let path = crate::dirs::manifest_path();
        std::fs::write(&path, raw).unwrap();

        assert_eq!(installed_cli_version().as_deref(), Some("0.11.1"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);

        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
