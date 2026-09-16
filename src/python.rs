// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! Discovery of Python interpreters already present on the host.
//!
//! Since D1 the launcher no longer *requires* a system Python — `uv` provisions
//! one when nothing usable turns up (see `uv::install_python`). Discovery still
//! runs first because reusing a suitable system interpreter saves a ~25 MB
//! download on the majority of hosts.
//!
//! On Windows, "on PATH" is not where Python usually is: the official installer
//! leaves *Add python.exe to PATH* unchecked, so the `py` launcher is the only
//! entry point. Discovery therefore also asks `py -0p` and the
//! `Software\Python\PythonCore` registry keys (#B7).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The minimum interpreter version the Huitzo CLI supports, as a tuple so the
/// gate is a single ordered comparison (`(3, 9) < (3, 11)`); comparing major
/// and minor independently wrongly accepted e.g. `4.0`.
pub const MIN_PYTHON: (u8, u8) = (3, 11);

/// Information about a discovered Python interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonInfo {
    pub path: PathBuf,
    pub version: (u8, u8),
    /// Where discovery found it — reported in the selection log so a user can
    /// see *why* a given interpreter was chosen.
    pub source: Source,
}

/// How an interpreter was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Found by name on `PATH`.
    Path,
    /// Listed by the Windows `py -0p` launcher.
    PyLauncher,
    /// Read from `HKCU`/`HKLM\Software\Python\PythonCore\*\InstallPath`.
    Registry,
    /// Downloaded by `uv python install` into `$HUITZO_HOME/python` because the
    /// host had nothing usable (D1).
    UvManaged,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Path => "PATH",
            Source::PyLauncher => "py launcher",
            Source::Registry => "registry",
            Source::UvManaged => "uv-managed",
        }
    }
}

/// Scan candidates in order matching the `bootws` check_python() pattern.
const CANDIDATES: &[&str] = &[
    "python3.14",
    "python3.13",
    "python3.12",
    "python3.11",
    "python3",
    "python",
];

/// True when `version` satisfies the minimum the CLI needs.
///
/// A single tuple comparison — `(major, minor) >= MIN_PYTHON`. The previous
/// `major >= 3 && minor >= 11` form accepted `4.11` but also rejected a
/// hypothetical `4.0`, i.e. it was wrong in both directions.
pub fn meets_minimum(version: (u8, u8)) -> bool {
    version >= MIN_PYTHON
}

/// True for a path inside a Microsoft Store `WindowsApps` directory.
///
/// `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe` is an app-execution alias:
/// a zero-byte reparse point that opens the Store instead of running Python. It
/// is on `PATH` by default on Windows, so discovery must not treat it as an
/// interpreter. `C:\Program Files\WindowsApps\<pkg>\python.exe` — the real Store
/// package — is excluded by the same rule on purpose: that tree is ACL'd so that
/// invoking it by full path is unreliable, and a uv-provisioned CPython is a
/// better base for the managed venv than an interpreter we may not be able to
/// re-exec later.
pub fn is_windows_store_path(path: &Path) -> bool {
    // Split on BOTH separators rather than using `Path::components`: on a Unix
    // build (which is where the unit tests run) `components` treats a whole
    // `C:\...\WindowsApps\python.exe` string as one component and the check
    // would silently never fire.
    path.to_string_lossy()
        .split(['/', '\\'])
        .any(|c| c.eq_ignore_ascii_case("WindowsApps"))
}

/// Discover every usable Python interpreter on this host, best first.
///
/// Never fails: an empty vector means "nothing usable here", which since D1 is a
/// normal, recoverable state (the caller provisions one with uv).
pub fn discover_all() -> Vec<PythonInfo> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();

    for (path, source) in candidate_paths() {
        // Deduplicate by canonical path — `python3` and `python3.12` are
        // usually the same file, and uv/pyenv shims shadow system Pythons.
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical) {
            continue;
        }
        if cfg!(windows) && is_windows_store_path(&path) {
            continue;
        }
        if let Some(version) = probe_version(&path) {
            if meets_minimum(version) {
                found.push(PythonInfo {
                    path,
                    version,
                    source,
                });
            }
        }
    }
    found
}

/// The candidates discovery will probe, each tagged with where it came from,
/// in preference order: `PATH` names first (cheapest, and what the user's shell
/// would pick), then the Windows-only sources.
///
/// The Windows sources are queried once each, here — never once per candidate.
fn candidate_paths() -> Vec<(PathBuf, Source)> {
    let mut paths = Vec::new();
    for candidate in CANDIDATES {
        // `which_all` rather than `which`: a pyenv/uv shim earlier in PATH
        // must not hide the system interpreter behind it.
        if let Ok(found) = which::which_all(candidate) {
            paths.extend(found.map(|p| (p, Source::Path)));
        }
    }
    paths.extend(
        py_launcher_paths()
            .into_iter()
            .map(|p| (p, Source::PyLauncher)),
    );
    paths.extend(registry_paths().into_iter().map(|p| (p, Source::Registry)));
    paths
}

/// Interpreters reported by the Windows `py` launcher (`py -0p`).
#[cfg(windows)]
fn py_launcher_paths() -> Vec<PathBuf> {
    let output = match Command::new("py")
        .arg("-0p")
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    parse_py_launcher_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(windows))]
fn py_launcher_paths() -> Vec<PathBuf> {
    Vec::new()
}

/// Parse `py -0p` output into interpreter paths.
///
/// Lines look like `` -V:3.12 *        C:\Python312\python.exe`` (the `*` marks
/// the default) or, on older launchers, `` -3.12-64           C:\Python312\...``.
/// The tag is whitespace-free, so everything after the first whitespace run —
/// minus a leading `*` — is the path, which keeps `C:\Program Files\...` intact.
// Off Windows only the unit tests call this; the parser stays compiled
// everywhere so a change to it is checked on every platform's CI leg.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_py_launcher_output(stdout: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('-') {
            continue;
        }
        // Split off the version tag, then an optional `*` default marker.
        let Some((_tag, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('*').unwrap_or(rest).trim_start();
        if rest.is_empty() {
            continue;
        }
        paths.push(PathBuf::from(rest));
    }
    paths
}

/// Interpreters registered under `Software\Python\PythonCore` (HKCU then HKLM).
///
/// Queried through `reg.exe` rather than a registry crate: the launcher ships to
/// every user and a new dependency costs binary size for one lookup that a
/// bundled Windows tool already does.
#[cfg(windows)]
fn registry_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for root in ["HKCU", "HKLM"] {
        let key = format!(r"{root}\Software\Python\PythonCore");
        let output = match Command::new("reg")
            .args(["query", &key, "/s", "/v", "ExecutablePath"])
            .stderr(std::process::Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => o,
            // Absent key (no Python registered under this hive) — not an error.
            _ => continue,
        };
        paths.extend(parse_reg_executable_paths(&String::from_utf8_lossy(
            &output.stdout,
        )));
    }
    paths
}

#[cfg(not(windows))]
fn registry_paths() -> Vec<PathBuf> {
    Vec::new()
}

/// Parse `reg query ... /v ExecutablePath` output into interpreter paths.
///
/// Value lines look like
/// `    ExecutablePath    REG_SZ    C:\Python312\python.exe`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_reg_executable_paths(stdout: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("ExecutablePath") else {
            continue;
        };
        let rest = rest.trim_start();
        // The type token (REG_SZ / REG_EXPAND_SZ) then the value.
        let Some((ty, value)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        if !ty.starts_with("REG_") {
            continue;
        }
        let value = value.trim();
        if !value.is_empty() {
            paths.push(PathBuf::from(value));
        }
    }
    paths
}

/// Split discovered interpreters into the ones the release feed can serve a
/// wheel to and the ones it cannot, discovery order preserved inside each group.
///
/// This is a *filter*, not a ranking (T14). The CLI ships only as a compiled
/// wheel, so building the managed venv on an interpreter with no matching wheel
/// produces an environment the install step must immediately refuse. Ranking
/// them second — the previous behaviour — is what made Debian 12 worse off than
/// a bare container: its stock Python 3.11 was picked up, a 3.11 venv was built
/// on it, and only then did the launcher declare the host unserviceable, while
/// a host with *no* Python at all was rescued by provisioning one. The caller
/// now builds only on the first group and provisions when it is empty.
///
/// The second group is returned so the caller can report what it skipped and
/// why — never so it can fall back to it.
///
/// A stable partition rather than a sort: discovery order already encodes the
/// host's own preference (newest named interpreter first, then `PATH` order).
pub fn partition_by_wheel(
    candidates: &[PythonInfo],
    has_wheel: impl Fn((u8, u8)) -> bool,
) -> (Vec<&PythonInfo>, Vec<&PythonInfo>) {
    candidates.iter().partition(|py| has_wheel(py.version))
}

/// Run the interpreter to extract its version.
pub fn probe_version(path: &Path) -> Option<(u8, u8)> {
    let output = Command::new(path)
        .args([
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?
        .wait_with_output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    parse_version(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `major.minor` (trailing components ignored) out of probe output.
fn parse_version(s: &str) -> Option<(u8, u8)> {
    let mut parts = s.trim().split('.');
    let major: u8 = parts.next()?.trim().parse().ok()?;
    let minor: u8 = parts.next()?.trim().parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(version: (u8, u8), path: &str) -> PythonInfo {
        PythonInfo {
            path: PathBuf::from(path),
            version,
            source: Source::Path,
        }
    }

    #[test]
    fn version_gate_compares_tuples_not_fields() {
        assert!(meets_minimum((3, 11)));
        assert!(meets_minimum((3, 12)));
        assert!(meets_minimum((3, 14)));
        assert!(!meets_minimum((3, 10)));
        assert!(!meets_minimum((3, 9)));
        assert!(!meets_minimum((2, 7)));
        // The field-wise gate `major >= 3 && minor >= 11` got both of these
        // wrong: it rejected 4.0 (a future major IS >= 3.11) and it accepted
        // 2.11 only because the major check happened to catch it.
        assert!(meets_minimum((4, 0)), "a future major must pass");
        assert!(!meets_minimum((2, 11)), "2.11 is below 3.11");
    }

    /// The live feed publishes cp312 and cp313 only.
    fn live_feed(v: (u8, u8)) -> bool {
        v == (3, 12) || v == (3, 13)
    }

    #[test]
    fn only_wheel_compatible_interpreters_are_offered_for_the_venv() {
        let candidates = vec![
            info((3, 14), "/usr/bin/python3.14"),
            info((3, 13), "/usr/bin/python3.13"),
            info((3, 12), "/usr/bin/python3.12"),
            info((3, 11), "/usr/bin/python3.11"),
        ];
        let (installable, skipped) = partition_by_wheel(&candidates, live_feed);
        assert_eq!(
            installable.iter().map(|p| p.version).collect::<Vec<_>>(),
            vec![(3, 13), (3, 12)]
        );
        // 3.14 and 3.11 are reported, not ranked last and then used: a venv on
        // either of them can only ever reach `Error::NoWheel`.
        assert_eq!(
            skipped.iter().map(|p| p.version).collect::<Vec<_>>(),
            vec![(3, 14), (3, 11)]
        );
    }

    #[test]
    fn a_debian_12_host_offers_nothing_and_must_therefore_provision() {
        // Debian 12 stock: `python3` is 3.11.2 and nothing else is present.
        // This is the T14 defect. The old `prefer_wheel_compatible` returned
        // this interpreter as the (only, last-ranked) candidate, the caller
        // built a 3.11 venv on it, and the install step then failed with
        // exit 78 — on a host a bare container would have been rescued from.
        let candidates = vec![info((3, 11), "/usr/bin/python3")];
        let (installable, skipped) = partition_by_wheel(&candidates, live_feed);
        assert!(
            installable.is_empty(),
            "a 3.11-only host has nothing to build on; the caller must provision"
        );
        assert_eq!(skipped.len(), 1, "and it must still be able to say why");
    }

    #[test]
    fn a_host_with_a_wheel_compatible_python_does_not_need_provisioning() {
        // The other half of the same decision: 3.12 is present, so the caller
        // reuses it and must NOT download a second interpreter.
        let candidates = vec![
            info((3, 11), "/usr/bin/python3.11"),
            info((3, 12), "/usr/bin/python3.12"),
        ];
        let (installable, _) = partition_by_wheel(&candidates, live_feed);
        assert_eq!(installable.len(), 1);
        assert_eq!(installable[0].path, PathBuf::from("/usr/bin/python3.12"));
    }

    #[test]
    fn discovery_order_is_stable_within_each_group() {
        // A release-feed outage (no wheels at all) must not reshuffle anything;
        // it empties the installable group and preserves the rest verbatim.
        let candidates = vec![
            info((3, 13), "/opt/first/python3.13"),
            info((3, 13), "/usr/bin/python3.13"),
            info((3, 12), "/usr/bin/python3.12"),
        ];
        let (installable, skipped) = partition_by_wheel(&candidates, |_| false);
        assert!(installable.is_empty());
        assert_eq!(
            skipped.iter().map(|p| p.path.clone()).collect::<Vec<_>>(),
            vec![
                PathBuf::from("/opt/first/python3.13"),
                PathBuf::from("/usr/bin/python3.13"),
                PathBuf::from("/usr/bin/python3.12"),
            ]
        );
        // Every candidate is still accounted for — the split must never drop one.
        assert_eq!(installable.len() + skipped.len(), candidates.len());
    }

    #[test]
    fn py_launcher_output_is_parsed_including_spaced_paths() {
        let stdout = concat!(
            " -V:3.12 *        C:\\Python312\\python.exe\r\n",
            " -V:3.11          C:\\Program Files\\Python311\\python.exe\r\n",
            "Installed Pythons found by C:\\WINDOWS\\py.exe\r\n",
        );
        assert_eq!(
            parse_py_launcher_output(stdout),
            vec![
                PathBuf::from(r"C:\Python312\python.exe"),
                PathBuf::from(r"C:\Program Files\Python311\python.exe"),
            ]
        );
    }

    #[test]
    fn registry_query_output_is_parsed() {
        let stdout = concat!(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\3.12\\InstallPath\r\n",
            "    ExecutablePath    REG_SZ    C:\\Python312\\python.exe\r\n",
            "\r\n",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\3.11\\InstallPath\r\n",
            "    ExecutablePath    REG_EXPAND_SZ    C:\\Program Files\\Python311\\python.exe\r\n",
        );
        assert_eq!(
            parse_reg_executable_paths(stdout),
            vec![
                PathBuf::from(r"C:\Python312\python.exe"),
                PathBuf::from(r"C:\Program Files\Python311\python.exe"),
            ]
        );
    }

    #[test]
    fn store_alias_stubs_are_recognised() {
        assert!(is_windows_store_path(Path::new(
            r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\python.exe"
        )));
        assert!(is_windows_store_path(Path::new(
            r"C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.11_x64__qbz5n2kfra8p0\python3.11.exe"
        )));
        assert!(!is_windows_store_path(Path::new(
            r"C:\Python312\python.exe"
        )));
        assert!(!is_windows_store_path(Path::new("/usr/bin/python3.12")));
    }

    #[test]
    fn discovered_interpreters_all_satisfy_the_gate() {
        // Whatever this host has, discovery must only ever return usable ones.
        for info in discover_all() {
            assert!(meets_minimum(info.version), "{info:?} is below MIN_PYTHON");
            assert!(info.path.exists());
        }
    }
}
