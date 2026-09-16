// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! End-to-end cover for `create_managed_venv`'s interpreter selection (R60).
//!
//! The pure helpers it composes — `python::partition_by_wheel`,
//! `python::discover_all`, `venv::create` — each have unit tests, but nothing
//! exercised the order they run in: which interpreter is built on, what happens
//! when that one fails, and when `uv python install` is reached. A selection
//! regression (the wheel filter dropped, the fallback loop broken, provisioning
//! attempted before the search or not at all) would have passed CI untouched.
//!
//! Since T14 the rule under test is a FILTER, not a ranking: an interpreter the
//! feed publishes no wheel for is named and skipped, never built on, and a host
//! that has only such interpreters provisions a CPython exactly like a host with
//! none. These tests pin both halves.
//!
//! So this drives the real binary against a controlled host:
//!   * `PATH` holds only fake interpreters we created, so discovery is exact;
//!   * `$HUITZO_HOME/bin/uv` is a stub that logs every invocation and can be
//!     told to fail for a specific interpreter;
//!   * the release feed is an httpmock server publishing exactly the live feed's
//!     ABI shape (cp312 + cp313).
//!
//! Unix only: the fakes are `#!/bin/sh` scripts. The Windows leg of this
//! selection is covered by the installer e2e matrix in
//! `.github/workflows/installer-e2e.yml` (which reaches a working CLI on a host
//! where only the `py` launcher is visible), not here.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use httpmock::prelude::*;
use tempfile::TempDir;

use huitzo_launcher::uv_manifest::PINNED_UV_VERSION;

/// The ABIs the mock feed publishes — the live `cli-release.json` shape. 3.11 is
/// deliberately absent: that is what makes "skipped, not built on" observable,
/// and it is the real Debian 12 / Ubuntu 22.04 situation T14 fixed.
const WHEEL_ABIS: [&str; 2] = ["cp312", "cp313"];

/// The CPython `create_managed_venv` provisions when nothing on the host can
/// take a wheel. Kept in step with `uv::PROVISIONED_PYTHON` by the assertions
/// below, which would fail loudly if it ever moved.
const PROVISIONED: &str = "3.13";

fn write_exec(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A fake interpreter that answers `probe_version`'s `-c` snippet with
/// `version`, whatever it is asked.
fn fake_python(dir: &Path, name: &str, version: &str) {
    write_exec(
        &dir.join(name),
        &format!("#!/bin/sh\necho {version}\nexit 0\n"),
    );
}

/// A stub `uv` that records each invocation to `$UV_STUB_LOG` and refuses every
/// interpreter whose path matches `$UV_STUB_REFUSE` (empty = refuse nothing).
///
/// On success it writes the same two things a real `uv venv --seed` leaves
/// behind and the launcher then reads back: `pyvenv.cfg` and `bin/python`.
const UV_STUB: &str = r#"#!/bin/sh
# The launcher under test runs with a PATH containing ONLY the fake
# interpreters, so that discovery is exact. `uv` is invoked by absolute path and
# is not subject to that; give the stub back the coreutils it needs.
PATH="$UV_STUB_PATH"
export PATH

log() { printf '%s\n' "$*" >> "$UV_STUB_LOG"; }

case "$1" in
  python)
    # uv python install <version>
    log "python-install $3"
    exit 0
    ;;
  venv)
    shift
    spec=""
    dest=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --python) spec="$2"; shift 2 ;;
        --seed)   shift ;;
        *)        dest="$1"; shift ;;
      esac
    done
    log "venv $spec"
    if [ -n "${UV_STUB_REFUSE:-}" ]; then
      case "$spec" in
        *"$UV_STUB_REFUSE"*)
          echo "stub uv: refusing $spec on purpose" >&2
          exit 1
          ;;
      esac
    fi
    # Report the interpreter the spec asked for, so the launcher's read-back of
    # the finished environment is honest rather than hard-coded.
    case "$spec" in
      *3.11*) version=3.11 ;;
      *3.12*) version=3.12 ;;
      *3.13*) version=3.13 ;;
      *)      version=3.13 ;;
    esac
    mkdir -p "$dest/bin"
    printf 'home = %s\nversion_info = %s.0\n' "$(dirname "$spec")" "$version" > "$dest/pyvenv.cfg"
    printf '#!/bin/sh\necho %s\nexit 0\n' "$version" > "$dest/bin/python"
    chmod +x "$dest/bin/python"
    exit 0
    ;;
esac
echo "stub uv: unhandled invocation: $*" >&2
exit 1
"#;

struct Host {
    home: TempDir,
    path_dir: TempDir,
    server: MockServer,
}

impl Host {
    /// A host with a staged stub `uv`, an empty `PATH` directory, and a feed
    /// publishing the live ABI set.
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();

        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        write_exec(&bin.join("uv"), UV_STUB);
        // The version stamp is what makes `ensure_uv` short-circuit instead of
        // downloading the real uv over our stub.
        fs::write(home.path().join("uv-version.txt"), PINNED_UV_VERSION).unwrap();

        let server = MockServer::start();
        let manifest_url = server.url("/cli-release.json");
        server.mock(|when, then| {
            when.method(GET).path("/releases");
            then.status(200).json_body(serde_json::json!([{
                "tag_name": "cli-v0.11.1",
                "created_at": "2026-09-01T00:00:00Z",
                "assets": [{
                    "name": "cli-release.json",
                    "browser_download_url": manifest_url,
                }],
            }]));
        });

        let mut wheels = serde_json::Map::new();
        for platform in ["linux-x86_64", "linux-aarch64", "macos-arm64"] {
            for abi in WHEEL_ABIS {
                wheels.insert(
                    format!("{platform}-{abi}"),
                    serde_json::json!({
                        "filename": format!("huitzo-0.11.1-{abi}-{abi}-{platform}.whl"),
                        "sha256": "0".repeat(64),
                    }),
                );
            }
        }
        server.mock(|when, then| {
            when.method(GET).path("/cli-release.json");
            then.status(200).json_body(serde_json::json!({
                "version": "0.11.1",
                "min_launcher_version": "0.1.0",
                "wheels": wheels,
            }));
        });

        Self {
            home,
            path_dir,
            server,
        }
    }

    fn add_python(&self, name: &str, version: &str) {
        fake_python(self.path_dir.path(), name, version);
    }

    fn fake(&self, name: &str) -> String {
        self.path_dir.path().join(name).display().to_string()
    }

    fn uv_log(&self) -> Vec<String> {
        fs::read_to_string(self.home.path().join("uv.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Run the launcher on this host. `refuse` is the interpreter substring the
    /// stub `uv` rejects.
    fn run(&self, refuse: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_huitzo"))
            // A clean slate: the developer's own proxy settings, GITHUB_TOKEN,
            // VIRTUAL_ENV or real PATH must not reach this run.
            .env_clear()
            .env("PATH", self.path_dir.path())
            .env("HOME", self.home.path())
            .env("HUITZO_HOME", self.home.path())
            .env("HUITZO_RELEASE_URL", self.server.url("/releases"))
            // The venv is the subject here, not the wheel. Point the wheel
            // download at the same mock server, which serves no wheel — so the
            // run always ends at the download with everything above it already
            // observed, and never reaches out to github.com.
            .env("HUITZO_RELEASE_DOWNLOAD_URL", self.server.url("/wheels"))
            // Delegate to the managed venv: no local-checkout detection (#53).
            .env("HUITZO_LAUNCHER_FORCE", "1")
            .env("HUITZO_SKIP_UPDATE_CHECK", "1")
            .env("HUITZO_ASSUME_YES", "1")
            .env("HUITZO_BOOTSTRAP_CONSENTED", "1")
            .env("UV_STUB_LOG", self.home.path().join("uv.log"))
            .env("UV_STUB_PATH", "/usr/bin:/bin")
            .env("UV_STUB_REFUSE", refuse)
            .arg("--version")
            .output()
            .unwrap()
    }
}

/// Index of `needle` in `haystack`, with the haystack in the panic message —
/// an ordering assertion that fails with "not found" and nothing else is not
/// worth having.
fn at(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("expected to find {needle:?} in:\n{haystack}"))
}

/// The venv was built and the run then died at the wheel download, which this
/// harness deliberately does not serve. Everything these tests assert happens
/// strictly before that point.
fn assert_reached_the_wheel_download(out: &Output, err: &str) {
    assert!(
        err.contains("Installing huitzo 0.11.1"),
        "the venv must have been built and the install attempted:\n{err}"
    );
    assert_ne!(out.status.code(), Some(0), "stderr:\n{err}");
}

/// Only interpreters the feed can serve a wheel to are built on; the rest are
/// named and skipped. A `uv venv` failure on one of the wheel-compatible ones
/// falls through to the next — and never falls back to a skipped one.
#[test]
fn only_wheel_compatible_interpreters_are_built_on_and_the_rest_are_named() {
    let host = Host::new();
    // Discovery order is 3.13, 3.12, 3.11 (python.rs CANDIDATES).
    host.add_python("python3.13", "3.13");
    host.add_python("python3.12", "3.12");
    host.add_python("python3.11", "3.11");

    // ... and uv refuses 3.13, so the run has to fall through to 3.12.
    let out = host.run("python3.13");
    let err = String::from_utf8_lossy(&out.stderr);

    // 3.11 is reported as skipped BEFORE anything is tried, and is never tried.
    let skipped = at(&err, "Skipping Python 3.11");
    assert!(
        err.contains("publishes no wheel for it"),
        "a skipped interpreter must say why:\n{err}"
    );
    assert!(
        !err.contains("Trying Python 3.11"),
        "3.11 has no wheel in the feed, so it must never be built on:\n{err}"
    );

    let tried_313 = at(&err, "Trying Python 3.13");
    let tried_312 = at(&err, "Trying Python 3.12");
    assert!(skipped < tried_313, "skips are reported first:\n{err}");
    assert!(
        tried_313 < tried_312,
        "discovery order is preserved inside the wheel-compatible group:\n{err}"
    );
    assert!(
        at(&err, "trying next...") > tried_313,
        "a uv venv failure must fall through to the next candidate:\n{err}"
    );
    assert!(
        err.contains("Using Python 3.12"),
        "the surviving candidate must be the one reported:\n{err}"
    );

    // The same story, observed from uv's side rather than from our own log line:
    // 3.11 was never even offered to it.
    assert_eq!(
        host.uv_log(),
        vec![
            format!("venv {}", host.fake("python3.13")),
            format!("venv {}", host.fake("python3.12")),
        ],
        "uv must be asked for the wheel-compatible interpreters only, in order"
    );
    assert_reached_the_wheel_download(&out, &err);
}

/// T14, end to end: a host whose only Python cannot take a published wheel
/// provisions one, exactly like a host with no Python at all. This is Debian 12
/// stock and Ubuntu 22.04 + `python3.11`; before T14 both built a 3.11 venv and
/// were then refused with exit 78.
#[test]
fn a_host_whose_only_python_has_no_wheel_provisions_one_instead() {
    let host = Host::new();
    host.add_python("python3.11", "3.11");

    let out = host.run("");
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(
        err.contains("Skipping Python 3.11"),
        "the unusable interpreter must be named, not silently dropped:\n{err}"
    );
    assert!(
        !err.contains("Trying Python"),
        "nothing on this host may be built on:\n{err}"
    );
    assert!(
        err.contains("No system Python can install a cli-v0.11.1 wheel"),
        "the provisioning fallback must announce itself:\n{err}"
    );
    assert_eq!(
        host.uv_log(),
        vec![
            format!("python-install {PROVISIONED}"),
            format!("venv {PROVISIONED}"),
        ],
        "provisioning must precede the venv, and the venv must use the provisioned spec"
    );
    assert!(
        err.contains(&format!("Using Python {PROVISIONED}")),
        "the provisioned interpreter must be reported:\n{err}"
    );
    assert_reached_the_wheel_download(&out, &err);
}

/// With nothing usable on the host, `uv python install` runs — and only after
/// the search, never instead of it.
#[test]
fn an_empty_host_provisions_a_python_only_after_searching() {
    let host = Host::new();
    // No interpreters added: PATH is an empty directory.

    let out = host.run("");
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(
        !err.contains("Trying Python") && !err.contains("Skipping Python"),
        "there was nothing to try and nothing to skip:\n{err}"
    );
    assert_eq!(
        host.uv_log(),
        vec![
            format!("python-install {PROVISIONED}"),
            format!("venv {PROVISIONED}"),
        ],
        "provisioning must precede the venv, and the venv must use the provisioned spec"
    );
    assert!(
        err.contains(&format!("Using Python {PROVISIONED}")),
        "the provisioned interpreter must be reported:\n{err}"
    );
    assert_reached_the_wheel_download(&out, &err);
}

/// An interpreter below the 3.11 floor is not a candidate at all — not even a
/// skipped one. It must not be offered to uv and then rejected, which would
/// leave a half-built venv behind.
#[test]
fn an_interpreter_below_the_floor_is_never_tried() {
    let host = Host::new();
    host.add_python("python3", "3.9");

    let out = host.run("");
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(
        !err.contains("3.9"),
        "3.9 is below the floor: discovery drops it before selection sees it:\n{err}"
    );
    assert_eq!(
        host.uv_log(),
        vec![
            format!("python-install {PROVISIONED}"),
            format!("venv {PROVISIONED}"),
        ],
        "the host has no usable interpreter, so uv provisions one"
    );
    assert_reached_the_wheel_download(&out, &err);
}
