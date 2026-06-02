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

use std::process::Command;

use serde::{Deserialize, Serialize};

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
    /// Whether the binary was resolved on `PATH`.
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
/// Pure of side effects beyond running each tool's `--version` (read-only,
/// no install, no network). Never logs secrets — only tool ids, paths, and
/// version strings are recorded.
pub fn probe() -> CapabilityReport {
    let host = probe_host();
    let tools = vec![
        probe_tool(
            "huitzo",
            "Huitzo CLI",
            &["huitzo"],
            &["--version"],
            true,
            Some("curl -sSf https://huitzo.ai/install.sh | sh"),
        ),
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

/// Run `<bin> <args>` and extract a version-looking token from stdout.
///
/// Returns the first whitespace token that starts with a digit (handles
/// `git version 2.43.0`, `claude 1.2.3`, `huitzo 0.5.2`). Falls back to the
/// trimmed first line if no digit token is found. Read-only; never fails the
/// probe — a tool that won't report a version is still "present".
fn probe_version(bin: &std::path::Path, args: &[&str]) -> Option<String> {
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
/// Returns the first whitespace token on the first non-empty line that
/// starts with an ASCII digit (handles `git version 2.43.0`, `claude 1.2.3`,
/// `huitzo 0.5.2`). Falls back to the trimmed first line if no digit-led
/// token exists; returns `None` only when there is no non-empty line. Pure +
/// side-effect-free so it is unit-testable without spawning a process.
fn parse_version_token(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().next()?.trim();
    if first_line.is_empty() {
        return None;
    }

    let token = first_line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()));

    Some(token.unwrap_or(first_line).to_string())
}

/// Classify the host OS / shell / WSL and derive support level.
fn probe_host() -> HostInfo {
    let os = normalized_os();
    let arch = std::env::consts::ARCH.to_string();
    let shell = current_shell();
    let wsl = is_wsl();

    let (support, unsupported_reason) = classify_support(&os, wsl);

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
/// Supported: macOS, Linux, and WSL. Native Windows (non-WSL) is explicitly
/// UNSUPPORTED — the runner's outbound daemon, POSIX exec path, and the
/// curl|sh bootstrap target a POSIX shell. Admin-locked corporate machines
/// are called out in the matrix doc but cannot be reliably auto-detected
/// from the launcher, so they are flagged in docs rather than here.
fn classify_support(os: &str, wsl: bool) -> (SupportLevel, Option<String>) {
    match os {
        "macos" | "linux" => (SupportLevel::Supported, None),
        "windows" if wsl => (SupportLevel::Supported, None),
        "windows" => (
            SupportLevel::Unsupported,
            Some(
                "Native Windows (non-WSL) is not yet officially supported. \
                 Install Huitzo inside WSL2 (Ubuntu) and run the bootstrap there. \
                 See docs/SUPPORT_MATRIX.md."
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

/// Per-OS git install hint for the probe's `install_hint`.
fn git_install_hint(os: &str) -> Option<&'static str> {
    match os {
        "macos" => Some("xcode-select --install   # or: brew install git"),
        "linux" => Some("sudo apt install git   # or your distro's package manager"),
        _ => Some("https://git-scm.com/downloads"),
    }
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

    #[test]
    fn classify_macos_and_linux_supported() {
        assert_eq!(classify_support("macos", false).0, SupportLevel::Supported);
        assert_eq!(classify_support("linux", false).0, SupportLevel::Supported);
    }

    #[test]
    fn classify_windows_non_wsl_unsupported_with_reason() {
        let (level, reason) = classify_support("windows", false);
        assert_eq!(level, SupportLevel::Unsupported);
        let reason = reason.expect("non-WSL Windows must carry a rationale");
        assert!(reason.contains("WSL"));
    }

    #[test]
    fn classify_windows_wsl_supported() {
        assert_eq!(classify_support("windows", true).0, SupportLevel::Supported);
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
        let (level, reason) = classify_support("freebsd", false);
        assert_eq!(level, SupportLevel::Unsupported);
        assert!(reason.unwrap().contains("freebsd"));
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
}
