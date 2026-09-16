// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! End-to-end cover for `create_managed_venv`'s interpreter ordering (R60).
//!
//! The pure helpers it composes — `python::prefer_wheel_compatible`,
//! `python::discover_all`, `venv::create` — each have unit tests, but nothing
//! exercised the order they run in: which interpreter is tried first, what
//! happens when that one fails, and when `uv python install` is reached. An
//! ordering regression (preference dropped, fallback loop broken, provisioning
//! attempted before the search) would have passed CI untouched.
//!
//! So this drives the real binary against a controlled host:
//!   * `PATH` holds only fake interpreters we created, so discovery is exact;
//!   * `$HUITZO_HOME/bin/uv` is a stub that logs every invocation and can be
//!     told to fail for a specific interpreter;
//!   * the release feed is an httpmock server publishing exactly one wheel key.
//!
//! Unix only: the fakes are `#!/bin/sh` scripts. The Windows leg of this
//! ordering is covered by the installer e2e matrix in
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

/// The only wheel key the mock feed publishes: CPython 3.11, on every platform
/// the test could run on. Deliberately NOT the newest interpreter on the fake
/// host — that is what makes "wheel-compatible first" observable.
const WHEEL_PYTHON: &str = "cp311";

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
    /// publishing exactly one wheel key.
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
        server.mock(|when, then| {
            when.method(GET).path("/cli-release.json");
            then.status(200).json_body(serde_json::json!({
                "version": "0.11.1",
                "min_launcher_version": "0.1.0",
                "wheels": {
                    format!("linux-x86_64-{WHEEL_PYTHON}"): {
                        "filename": format!("huitzo-0.11.1-{WHEEL_PYTHON}-{WHEEL_PYTHON}-manylinux_2_17_x86_64.whl"),
                        "sha256": "0".repeat(64),
                    },
                    format!("linux-aarch64-{WHEEL_PYTHON}"): {
                        "filename": format!("huitzo-0.11.1-{WHEEL_PYTHON}-{WHEEL_PYTHON}-manylinux_2_17_aarch64.whl"),
                        "sha256": "0".repeat(64),
                    },
                    format!("macos-arm64-{WHEEL_PYTHON}"): {
                        "filename": format!("huitzo-0.11.1-{WHEEL_PYTHON}-{WHEEL_PYTHON}-macosx_11_0_arm64.whl"),
                        "sha256": "0".repeat(64),
                    },
                },
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

/// The interpreter that can actually be served a wheel is tried FIRST, even
/// when discovery found a newer one, and a `uv venv` failure falls through to
/// the next candidate instead of aborting the bootstrap.
#[test]
fn wheel_compatible_interpreter_is_tried_first_and_a_failure_falls_through() {
    let host = Host::new();
    // Discovery order is `python3.13` then `python3.11` (python.rs CANDIDATES).
    // The feed only has a cp311 wheel, so the ATTEMPT order must be the reverse.
    host.add_python("python3.13", "3.13");
    host.add_python("python3.11", "3.11");

    // ... and 3.11 is refused by uv, so the run has to fall through to 3.13.
    let out = host.run("python3.11");
    let err = String::from_utf8_lossy(&out.stderr);

    let tried_311 = at(&err, "Trying Python 3.11");
    let tried_313 = at(&err, "Trying Python 3.13");
    assert!(
        tried_311 < tried_313,
        "the wheel-compatible interpreter must be tried first:\n{err}"
    );
    assert!(
        err.contains("(has compiled wheel)"),
        "the wheel-compatible candidate must be labelled as such:\n{err}"
    );
    assert!(
        at(&err, "trying next...") > tried_311,
        "a uv venv failure must fall through to the next candidate:\n{err}"
    );
    assert!(
        err.contains("Using Python 3.13"),
        "the surviving candidate must be the one reported:\n{err}"
    );

    // The same order, observed from uv's side rather than from our own log line.
    let log = host.uv_log();
    assert_eq!(
        log,
        vec![
            format!("venv {}/python3.11", host.path_dir.path().display()),
            format!("venv {}/python3.13", host.path_dir.path().display()),
        ],
        "uv must be asked for the interpreters in preference order, once each"
    );
    assert!(
        !log.iter().any(|l| l.starts_with("python-install")),
        "a host with a usable Python must not download another one:\n{log:#?}"
    );

    // Terminal state: the venv exists on 3.13 and there is no cp313 wheel, so
    // the run ends on NoWheel (78) rather than silently installing something.
    assert_eq!(out.status.code(), Some(78), "stderr:\n{err}");
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
        !err.contains("Trying Python"),
        "there was nothing to try:\n{err}"
    );
    assert!(
        err.contains("No usable system Python"),
        "the provisioning fallback must announce itself:\n{err}"
    );

    assert_eq!(
        host.uv_log(),
        vec!["python-install 3.13".to_string(), "venv 3.13".to_string(),],
        "provisioning must precede the venv, and the venv must use the provisioned spec"
    );
    assert!(
        err.contains("Using Python 3.13"),
        "the provisioned interpreter must be reported:\n{err}"
    );
    assert_eq!(out.status.code(), Some(78), "stderr:\n{err}");
}

/// An interpreter below the 3.11 floor is not a candidate at all — it must not
/// be tried and then rejected, which would leave a half-built venv behind.
#[test]
fn an_interpreter_below_the_floor_is_never_tried() {
    let host = Host::new();
    host.add_python("python3", "3.9");

    let out = host.run("");
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(
        !err.contains("Trying Python 3.9"),
        "3.9 is below the floor and must never be offered to uv:\n{err}"
    );
    assert_eq!(
        host.uv_log(),
        vec!["python-install 3.13".to_string(), "venv 3.13".to_string(),],
        "the host has no usable interpreter, so uv provisions one"
    );
    assert_eq!(out.status.code(), Some(78), "stderr:\n{err}");
}
