// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use std::path::Path;
use std::process::Command;

use crate::dirs;
use crate::errors::Error;

/// Install a compiled wheel from a local file path into the managed venv.
///
/// Uses `pip install --force-reinstall` to ensure the compiled wheel replaces
/// any previously installed version.
pub fn install_wheel(wheel_path: &Path) -> Result<(), Error> {
    let python = dirs::venv_python();
    let output = Command::new(&python)
        .args([
            "-m",
            "pip",
            "install",
            "--force-reinstall",
            "--quiet",
            &wheel_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| Error::PipInstall(format!("Failed to run pip install wheel: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::PipInstall(format!(
            "Failed to install wheel: {stderr}"
        )));
    }

    Ok(())
}

/// The probe `verify_install` runs inside the managed venv.
///
/// It reproduces the launcher's own entry point rather than approximating it.
/// `import huitzo_cli` alone is NOT sufficient: the PyPI `huitzo` 0.2.0
/// placeholder (#B4) ships an importable `huitzo_cli` package with no
/// `__main__`, so the import succeeds and `python -m huitzo_cli` — what
/// `exec.rs` actually runs — still dies with "cannot be directly executed".
/// `find_spec("huitzo_cli.__main__")` is the precise precondition for `-m`.
const VERIFY_SCRIPT: &str = r#"
import importlib, importlib.util, sys
importlib.import_module('huitzo_cli')
if importlib.util.find_spec('huitzo_cli.__main__') is None:
    sys.exit("huitzo_cli imports, but the package has no __main__ module, "
             "so 'python -m huitzo_cli' cannot start it")
from importlib.metadata import version
print(version('huitzo'))
"#;

/// Prove the managed venv can actually run the CLI, and report its version.
///
/// Called immediately after every install (M8). Before this existed the only
/// `import huitzo_cli` probe was `venv::is_healthy()`, which runs at the *start
/// of the next launch* — so a bootstrap could print "Installed huitzo 0.2.0"
/// and then exec a module that did not exist. Nothing may print success until
/// this returns `Ok`.
///
/// `wheel` is the artefact being vouched for; it appears in the error so a bad
/// release is identifiable from a user's paste.
pub fn verify_install(wheel: &str) -> Result<String, Error> {
    let python = dirs::venv_python();
    // `-P` for the same reason `exec.rs` uses it: without it a `huitzo_cli/`
    // directory in the cwd would satisfy the import, and the check would vouch
    // for code the real invocation will never load.
    let output = Command::new(&python)
        .args(["-P", "-c", VERIFY_SCRIPT])
        .output();
    interpret_probe(output, &python.display().to_string(), wheel)
}

/// Map the probe's raw result onto the launcher's error contract.
///
/// Split from the spawn so the three outcomes that matter — interpreter would
/// not start, probe rejected the install, probe passed but named no version —
/// are testable without a venv on the machine running the tests.
fn interpret_probe(
    output: std::io::Result<std::process::Output>,
    python: &str,
    wheel: &str,
) -> Result<String, Error> {
    let fail = |detail: String| Error::InstallVerify {
        wheel: wheel.to_string(),
        python: python.to_string(),
        detail,
    };

    let output = output.map_err(|e| fail(format!("could not run the interpreter: {e}")))?;

    if !output.status.success() {
        return Err(fail(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        return Err(fail(
            "the import succeeded but the `huitzo` distribution reports no version".to_string(),
        ));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_detail(e: Error) -> (String, String) {
        match e {
            Error::InstallVerify { wheel, detail, .. } => (wheel, detail),
            other => panic!("expected InstallVerify, got: {other}"),
        }
    }

    /// Build an `Output` without spawning anything. `ExitStatus` has no public
    /// constructor, so borrow one from a process that is guaranteed to exist.
    fn output(ok: bool, stdout: &str, stderr: &str) -> std::io::Result<std::process::Output> {
        #[cfg(unix)]
        let status = Command::new("sh")
            .args(["-c", if ok { "exit 0" } else { "exit 1" }])
            .status()
            .unwrap();
        #[cfg(windows)]
        let status = Command::new("cmd")
            .args(["/C", if ok { "exit 0" } else { "exit 1" }])
            .status()
            .unwrap();
        Ok(std::process::Output {
            status,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    #[test]
    fn a_passing_probe_yields_the_version() {
        let v = interpret_probe(output(true, "0.11.1\n", ""), "/venv/python", "w.whl").unwrap();
        assert_eq!(v, "0.11.1");
    }

    #[test]
    fn a_failing_probe_names_the_wheel_and_quotes_the_interpreter() {
        let (wheel, detail) = err_detail(
            interpret_probe(
                output(
                    false,
                    "",
                    "ModuleNotFoundError: No module named 'huitzo_cli'\n",
                ),
                "/venv/python",
                "huitzo-0.11.1-cp312-cp312-manylinux_2_28_x86_64.whl",
            )
            .unwrap_err(),
        );
        assert_eq!(wheel, "huitzo-0.11.1-cp312-cp312-manylinux_2_28_x86_64.whl");
        assert!(detail.contains("No module named 'huitzo_cli'"), "{detail}");
    }

    #[test]
    fn a_probe_that_prints_nothing_is_a_failure_not_an_unknown_version() {
        // The pre-M8 code wrote `unwrap_or("unknown")` here and carried on.
        let (_, detail) = err_detail(
            interpret_probe(output(true, "  \n", ""), "/venv/python", "w.whl").unwrap_err(),
        );
        assert!(detail.contains("no version"), "{detail}");
    }

    #[test]
    fn an_interpreter_that_will_not_start_is_an_install_verify_failure() {
        let e = verify_install_would_spawn_nothing();
        let (_, detail) = err_detail(e);
        assert!(detail.contains("could not run the interpreter"), "{detail}");
    }

    fn verify_install_would_spawn_nothing() -> Error {
        let missing = std::path::Path::new("definitely-not-an-interpreter-ab12cd34");
        interpret_probe(
            Command::new(missing).arg("-V").output(),
            &missing.display().to_string(),
            "w.whl",
        )
        .unwrap_err()
    }

    // --- the probe script itself, against a real interpreter ---------------

    /// Any Python 3.8+ can run `VERIFY_SCRIPT`; the managed venv's 3.11+ is not
    /// required to test what the script decides.
    /// `None` only on Windows, where a hosted runner may genuinely have no
    /// `python` on PATH. On Unix — where this repo's own gate already shells
    /// `python3` — an absent interpreter is a broken environment, not a reason
    /// to quietly skip the checks that close #B4.
    fn some_python() -> Option<std::path::PathBuf> {
        let found = which::which("python3")
            .or_else(|_| which::which("python"))
            .ok();
        assert!(
            found.is_some() || cfg!(windows),
            "no python3/python on PATH: the probe tests would verify nothing"
        );
        found
    }

    /// `sys.path` fixture: a directory laid out like an installed environment.
    /// `main` controls whether `huitzo_cli/__main__.py` exists — the single bit
    /// that separates a working CLI from the #B4 placeholder.
    fn fixture(pkg: bool, main: bool, version: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        if pkg {
            let p = dir.path().join("huitzo_cli");
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("__init__.py"), "").unwrap();
            if main {
                std::fs::write(p.join("__main__.py"), "print('cli')\n").unwrap();
            }
            let d = dir.path().join(format!("huitzo-{version}.dist-info"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("METADATA"),
                format!("Metadata-Version: 2.1\nName: huitzo\nVersion: {version}\n"),
            )
            .unwrap();
        }
        dir
    }

    /// Run the real `VERIFY_SCRIPT` with `dir` as the working directory, which
    /// `python -c` puts on `sys.path`. (`-P` is deliberately omitted here: it
    /// is what keeps the cwd OFF `sys.path` in production, and the fixture is
    /// how the test stands in for an installed environment.)
    fn run_probe(dir: &std::path::Path) -> Option<Result<String, Error>> {
        let python = some_python()?;
        Some(interpret_probe(
            Command::new(&python)
                .args(["-c", VERIFY_SCRIPT])
                .current_dir(dir)
                .output(),
            &python.display().to_string(),
            "fixture.whl",
        ))
    }

    #[test]
    fn probe_accepts_an_installation_that_can_actually_start() {
        let dir = fixture(true, true, "0.11.1");
        let Some(result) = run_probe(dir.path()) else {
            return;
        };
        assert_eq!(result.unwrap(), "0.11.1");
    }

    /// The exact #B4 shape: PyPI `huitzo` 0.2.0 ships an importable
    /// `huitzo_cli` package with no `__main__`, so `import huitzo_cli` alone
    /// says "fine" and `python -m huitzo_cli` then dies. The probe must reject
    /// it, or M8 is only half fixed.
    #[test]
    fn probe_rejects_a_package_with_no_main_module() {
        let dir = fixture(true, false, "0.2.0");
        let Some(result) = run_probe(dir.path()) else {
            return;
        };
        let (_, detail) = err_detail(result.unwrap_err());
        assert!(detail.contains("__main__"), "{detail}");
    }

    #[test]
    fn probe_rejects_a_missing_package() {
        let dir = fixture(false, false, "0.0.0");
        let Some(result) = run_probe(dir.path()) else {
            return;
        };
        let (_, detail) = err_detail(result.unwrap_err());
        assert!(detail.contains("huitzo_cli"), "{detail}");
    }
}
