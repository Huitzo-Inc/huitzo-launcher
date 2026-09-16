// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! End-to-end coverage for release selection (#48), the release feed's
//! launcher floor (M10), and the update bookkeeping in the manifest (M13/M14).
//!
//! `fetch_cli_release` used to take the *first* `cli-v*` entry in the GitHub
//! releases array. Every `cli-v*` release shares one `created_at` (they are
//! all tagged off the same commit) and the API sorts by `created_at`, so that
//! order is arbitrary — in production it resolved `cli-v0.9.0` as "latest"
//! while `cli-v0.10.1` existed. These tests drive the real function against a
//! mocked releases endpoint via `HUITZO_RELEASE_URL`.

use std::sync::{Mutex, MutexGuard};

use httpmock::MockServer;
use huitzo_launcher::download;
use huitzo_launcher::manifest::{self, Manifest, PendingUpdate};
use huitzo_launcher::update;

mod common;

/// `HUITZO_RELEASE_URL` is process-global; serialize the tests that set it.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Points `fetch_cli_release` at a mock server for the life of the guard.
struct ReleaseUrl {
    _guard: MutexGuard<'static, ()>,
}

impl ReleaseUrl {
    fn set(url: &str) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HUITZO_RELEASE_URL", url) };
        Self { _guard: guard }
    }
}

impl Drop for ReleaseUrl {
    fn drop(&mut self) {
        unsafe { std::env::remove_var("HUITZO_RELEASE_URL") };
    }
}

/// A releases-array entry carrying a `cli-release.json` asset served by `server`.
fn cli_entry(server: &MockServer, version: &str, draft: bool) -> serde_json::Value {
    serde_json::json!({
        "tag_name": format!("cli-v{version}"),
        // Identical across every cli-v* release, exactly as in production —
        // this is why array order tells us nothing about which is newest.
        "created_at": "2026-07-20T04:26:37Z",
        "published_at": "2026-07-30T03:17:15Z",
        "draft": draft,
        // Every cli-v* release ships as a prerelease. Selection must keep them.
        "prerelease": true,
        "assets": [{
            "name": "cli-release.json",
            "browser_download_url": server.url(format!("/cli-release-{version}.json")),
        }],
    })
}

/// Serves the `cli-release.json` manifest for one CLI version.
fn mock_manifest(server: &MockServer, version: &str) {
    mock_manifest_with_floor(server, version, "0.1.0");
}

/// Same, with an explicit `min_launcher_version` floor (M10).
fn mock_manifest_with_floor(server: &MockServer, version: &str, floor: &str) {
    let body = serde_json::json!({
        "version": version,
        "min_launcher_version": floor,
        "wheels": {
            "linux-x86_64": {
                "filename": format!("huitzo_cli-{version}-py3-none-any.whl"),
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            }
        },
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/cli-release-{version}.json"));
        then.status(200).json_body(body);
    });
}

fn mock_releases(server: &MockServer, releases: serde_json::Value) {
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/releases");
        then.status(200).json_body(releases);
    });
}

/// Regression test for #48, built from the real API page in the issue:
/// `cli-v0.9.0` first, `cli-v0.10.1` at index 4, identical `created_at`,
/// every entry a prerelease. Against the pre-fix `.find(...)` this resolves
/// to 0.9.0.
#[test]
fn fetch_cli_release_picks_newest_not_first_in_array() {
    let server = MockServer::start();
    for v in ["0.9.0", "0.8.0", "0.7.0", "0.10.1", "0.10.0"] {
        mock_manifest(&server, v);
    }
    mock_releases(
        &server,
        serde_json::json!([
            cli_entry(&server, "0.9.0", false),
            cli_entry(&server, "0.8.0", false),
            // A launcher release interleaved in the page, as in production.
            {"tag_name": "v0.3.2", "draft": false, "prerelease": false, "assets": []},
            cli_entry(&server, "0.7.0", false),
            cli_entry(&server, "0.10.1", false),
            cli_entry(&server, "0.10.0", false),
        ]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let release = download::fetch_cli_release().expect("release should resolve");

    assert_eq!(
        release.version, "0.10.1",
        "0.10.1 is newer than 0.9.0; picking by array position pins users on 0.9.0"
    );
    assert_eq!(release.min_launcher_version, "0.1.0");
    assert!(!release.wheels.is_empty());
}

/// Prereleases MUST stay eligible: every `cli-v*` release is marked
/// `prerelease: true`, so filtering on that flag would leave the launcher
/// unable to find any CLI release at all.
#[test]
fn fetch_cli_release_accepts_a_prerelease_only_page() {
    let server = MockServer::start();
    mock_manifest(&server, "0.10.1");
    mock_releases(
        &server,
        serde_json::json!([cli_entry(&server, "0.10.1", false)]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let release = download::fetch_cli_release().expect("a prerelease is still a CLI release");
    assert_eq!(release.version, "0.10.1");
}

/// Drafts are unpublished and must never be offered as an update, even when
/// they carry the highest version.
#[test]
fn fetch_cli_release_skips_draft_releases() {
    let server = MockServer::start();
    mock_manifest(&server, "0.11.0");
    mock_manifest(&server, "0.10.1");
    mock_releases(
        &server,
        serde_json::json!([
            cli_entry(&server, "0.11.0", true),
            cli_entry(&server, "0.10.1", false),
        ]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let release = download::fetch_cli_release().expect("release should resolve");
    assert_eq!(release.version, "0.10.1");
}

/// A malformed tag must neither panic nor outrank a well-formed newer one.
#[test]
fn fetch_cli_release_ignores_malformed_tags() {
    let server = MockServer::start();
    mock_manifest(&server, "0.10.1");
    mock_releases(
        &server,
        serde_json::json!([
            {"tag_name": "cli-vfoo", "draft": false, "prerelease": true, "assets": []},
            {"tag_name": "cli-v", "draft": false, "prerelease": true, "assets": []},
            cli_entry(&server, "0.10.1", false),
        ]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let release = download::fetch_cli_release().expect("release should resolve");
    assert_eq!(release.version, "0.10.1");
}

/// A tag the launcher cannot order in full (`cli-v0.11.0-rc1`) must not be
/// ranked as the truncated version it parses to — that would let it beat a
/// genuinely newer release.
#[test]
fn fetch_cli_release_skips_a_version_it_cannot_order() {
    let server = MockServer::start();
    mock_manifest(&server, "0.10.1");
    mock_releases(
        &server,
        serde_json::json!([
            {"tag_name": "cli-v0.11.0-rc1", "draft": false, "prerelease": true, "assets": []},
            cli_entry(&server, "0.10.1", false),
        ]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let release = download::fetch_cli_release().expect("release should resolve");
    assert_eq!(release.version, "0.10.1");
}

/// No `cli-v*` entry at all is an error, not a launcher release mistaken for one.
#[test]
fn fetch_cli_release_errors_when_no_cli_release_exists() {
    let server = MockServer::start();
    mock_releases(
        &server,
        serde_json::json!([
            {"tag_name": "v0.3.2", "draft": false, "prerelease": false, "assets": []},
        ]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let err = download::fetch_cli_release().expect_err("no cli-v* tag means no CLI release");
    assert!(
        format!("{err}").contains("cli-v*"),
        "unexpected error message: {err}"
    );
}

// --- M10: the feed's launcher floor is enforced, not just parsed ----------

/// A release that declares a launcher floor above this launcher must be
/// refused — with the command that fixes it, not a generic feed error. Before
/// T3 the field was parsed and dropped (`#[allow(dead_code)]`), so an
/// out-of-date launcher happily installed a CLI it was never cleared for.
#[test]
fn fetch_cli_release_refuses_a_release_that_needs_a_newer_launcher() {
    let server = MockServer::start();
    mock_manifest_with_floor(&server, "0.11.1", "99.0.0");
    mock_releases(
        &server,
        serde_json::json!([cli_entry(&server, "0.11.1", false)]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let err = download::fetch_cli_release().expect_err("the floor must be enforced");
    let msg = format!("{err}");
    assert!(msg.contains("99.0.0"), "{msg}");
    assert!(msg.contains("0.11.1"), "{msg}");
    assert!(
        msg.contains("--launcher-update") || msg.contains("brew upgrade"),
        "the refusal must name the upgrade path: {msg}"
    );
}

/// A floor at or below this launcher proceeds exactly as before.
#[test]
fn fetch_cli_release_proceeds_when_the_floor_is_satisfied() {
    let server = MockServer::start();
    mock_manifest_with_floor(&server, "0.11.1", env!("CARGO_PKG_VERSION"));
    mock_releases(
        &server,
        serde_json::json!([cli_entry(&server, "0.11.1", false)]),
    );

    let _env = ReleaseUrl::set(&server.url("/releases"));
    let release = download::fetch_cli_release().expect("a satisfied floor must not refuse");
    assert_eq!(release.version, "0.11.1");
}

// --- M13 / M14: what the manifest is allowed to record --------------------

fn write_manifest(pending: Option<PendingUpdate>) {
    manifest::save(&Manifest {
        schema_version: 3,
        python_path: "/usr/bin/python3.13".to_string(),
        python_version: "3.13".to_string(),
        huitzo_version: "0.11.0".to_string(),
        launcher_version: "0.3.2".to_string(),
        last_update_check: 0,
        pending_update: pending,
        created_at: 0,
        install_source: Some("github_release".to_string()),
        wheel_platform: Some("linux-x86_64".to_string()),
        active_deployment: None,
        capability_cache: None,
    })
    .unwrap();
}

fn staged(kind: &str, version: &str) -> PendingUpdate {
    PendingUpdate {
        kind: kind.to_string(),
        version: version.to_string(),
        attempts: 0,
        last_attempt: 0,
        last_error: None,
    }
}

/// M13: settling a deferral (Homebrew, or "already current") must clear the
/// staged record without moving `launcher_version` — that field may only ever
/// name a binary that is actually on disk.
#[test]
fn settling_without_an_install_leaves_launcher_version_alone() {
    let _home = common::TempHome::new();
    write_manifest(Some(staged("launcher", "0.3.3")));

    update::settle_pending(None);

    let m = manifest::load().unwrap();
    assert!(m.pending_update.is_none(), "the record must settle");
    assert_eq!(
        m.launcher_version, "0.3.2",
        "a Homebrew deferral installs nothing, so the manifest must not claim 0.3.3"
    );
}

/// The counterpart: a real install is the one thing that moves the version.
#[test]
fn settling_after_an_install_records_the_version_that_was_installed() {
    let _home = common::TempHome::new();
    write_manifest(Some(staged("launcher", "0.3.3")));

    update::settle_pending(Some("0.3.3"));

    let m = manifest::load().unwrap();
    assert!(m.pending_update.is_none());
    assert_eq!(m.launcher_version, "0.3.3");
}

/// M14: a failure is recorded against the staged update, and the very next
/// launch reads that record and declines to try again.
#[test]
fn a_recorded_failure_stops_the_next_launch_from_retrying() {
    let _home = common::TempHome::new();
    write_manifest(Some(staged("launcher", "0.3.3")));

    update::record_failed_attempt(
        "launcher",
        "0.3.3",
        "Self-update failed: Access is denied. (os error 5)\nsecond line",
    );

    let m = manifest::load().unwrap();
    let pending = m
        .pending_update
        .expect("the update stays staged for a retry");
    assert_eq!(pending.attempts, 1);
    assert!(pending.last_attempt > 0);
    assert_eq!(
        pending.last_error.as_deref(),
        Some("Self-update failed: Access is denied. (os error 5)"),
        "only the first line is stored"
    );
    assert!(
        !update::should_attempt(&pending, manifest::now_secs()),
        "the next invocation must not re-download the same binary"
    );
    assert!(
        update::deferral_notice(&pending).contains("Access is denied"),
        "the deferral must say why"
    );
}

/// A failure must be charged to the update that actually failed. If the daily
/// check staged something else in between, that record is left untouched.
#[test]
fn a_failure_is_not_charged_to_a_different_staged_update() {
    let _home = common::TempHome::new();
    write_manifest(Some(staged("wheel", "0.12.0")));

    update::record_failed_attempt("launcher", "0.3.3", "boom");

    let pending = manifest::load().unwrap().pending_update.unwrap();
    assert_eq!(pending.kind, "wheel");
    assert_eq!(pending.attempts, 0);
    assert!(pending.last_error.is_none());
}
