//! Integration tests for the in-launcher capability prober.
//!
//! Exercises the prober through the library surface (`huitzo_launcher::prober`)
//! the way S56's Hub-side wiring will consume it: produce a report, assert the
//! stable JSON shape, and confirm the readiness/gap derivations.
//!
//! Roadmap: docs/roadmaps/huitzo-studio.md row S55.

use huitzo_launcher::prober::{self, REPORT_SCHEMA_VERSION, SupportLevel};

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
