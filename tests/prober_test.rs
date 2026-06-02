//! Integration tests for the in-launcher capability prober.
//!
//! Exercises the prober through the library surface (`huitzo_launcher::prober`)
//! the way S56's Hub-side wiring will consume it: produce a report, assert the
//! stable JSON shape, and confirm the readiness/gap derivations.
//!
//! Roadmap: docs/roadmaps/huitzo-studio.md row S55.

use huitzo_launcher::prober::{
    self, CapabilityReport, HostInfo, REPORT_SCHEMA_VERSION, SupportLevel, ToolProbe,
};

#[test]
fn probe_emits_three_required_tools_with_stable_ids() {
    let report = prober::probe();
    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);

    // The three runner prerequisites are always probed, in a stable order,
    // and all are required.
    let ids: Vec<&str> = report.tools.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["huitzo", "claude", "git"]);
    assert!(report.tools.iter().all(|t| t.required));
}

#[test]
fn report_json_round_trips_and_preserves_shape() {
    let report = prober::probe();
    let json = serde_json::to_string(&report).expect("serialize");
    let back: prober::CapabilityReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, back);

    // The Hub consumer keys on these top-level fields; assert they exist.
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = value.as_object().unwrap();
    assert!(obj.contains_key("schema_version"));
    assert!(obj.contains_key("launcher_version"));
    assert!(obj.contains_key("host"));
    assert!(obj.contains_key("tools"));

    let host = obj["host"].as_object().unwrap();
    assert!(host.contains_key("os"));
    assert!(host.contains_key("arch"));
    assert!(host.contains_key("wsl"));
    assert!(host.contains_key("support"));
}

#[test]
fn host_support_is_supported_on_this_unix_runner() {
    // CI runs on macOS / Linux / Windows. On the two Unix targets the host
    // must classify as supported; on Windows-non-WSL it must be unsupported
    // and carry a rationale. (WSL is not present in CI, so we branch on OS.)
    let report = prober::probe();
    match std::env::consts::OS {
        "macos" | "linux" => {
            assert_eq!(report.host.support, SupportLevel::Supported);
            assert!(report.host.unsupported_reason.is_none());
        }
        "windows" if !report.host.wsl => {
            assert_eq!(report.host.support, SupportLevel::Unsupported);
            assert!(report.host.unsupported_reason.is_some());
        }
        _ => {}
    }
}

#[test]
fn ready_matches_missing_required_emptiness() {
    let report = prober::probe();
    // Internal consistency: ready() iff there are no missing required tools.
    assert_eq!(report.ready(), report.missing_required().is_empty());
}

/// Build a synthetic MIXED-state report so readiness/gap derivations are
/// asserted directly rather than relying on the (uniform) CI runner state.
fn synthetic_report(tools: Vec<ToolProbe>) -> CapabilityReport {
    CapabilityReport {
        schema_version: REPORT_SCHEMA_VERSION,
        launcher_version: "0.0.0-test".to_string(),
        host: HostInfo {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            shell: Some("bash".to_string()),
            wsl: false,
            support: SupportLevel::Supported,
            unsupported_reason: None,
        },
        tools,
    }
}

fn tool(id: &str, present: bool, required: bool) -> ToolProbe {
    ToolProbe {
        id: id.to_string(),
        display_name: id.to_string(),
        present,
        path: present.then(|| format!("/usr/bin/{id}")),
        version: present.then(|| "1.0.0".to_string()),
        required,
        install_hint: (!present).then(|| format!("install {id}")),
    }
}

#[test]
fn mixed_report_ready_and_gaps_are_exact() {
    // One required-missing → not ready, that one is the only gap.
    let r = synthetic_report(vec![
        tool("huitzo", true, true),
        tool("claude", true, true),
        tool("git", false, true),
    ]);
    assert!(!r.ready());
    assert_eq!(r.missing_required(), vec!["git".to_string()]);

    // An OPTIONAL tool missing must NOT block readiness.
    let r = synthetic_report(vec![
        tool("huitzo", true, true),
        tool("claude", true, true),
        tool("git", true, true),
        tool("optional-extra", false, false),
    ]);
    assert!(r.ready(), "missing optional tool must not block readiness");
    assert!(r.missing_required().is_empty());

    // All required present → ready, no gaps.
    let r = synthetic_report(vec![tool("huitzo", true, true), tool("git", true, true)]);
    assert!(r.ready());
    assert!(r.missing_required().is_empty());
}
