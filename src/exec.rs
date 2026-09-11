// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

use std::path::Path;

use crate::errors::Error;

/// Replace the current process with the Python CLI.
///
/// On Unix, this uses `execvp()` — the launcher process is replaced entirely.
/// On Windows, this spawns a child process and propagates its exit code.
///
/// Sets `HUITZO_MANAGED=1` so the Python CLI can detect it is running under
/// the launcher (e.g., to suppress "run pip install --upgrade" messages).
///
/// `safe_path` adds `-P` (Python 3.11+), keeping the invocation directory off
/// `sys.path`. Always true for the managed venv (guaranteed 3.11+ by
/// `python::discover_all`); for a locally detected interpreter (#53) the
/// caller reports what that venv's `pyvenv.cfg` says, because `-P` on an
/// older interpreter is a hard startup error.
pub fn exec_into_python(venv_python: &Path, args: &[String], safe_path: bool) -> Result<(), Error> {
    // Signal to the Python CLI that it's running under the launcher, and make the
    // bundled `uv` reachable (huitzo#965 / task #38): export HUITZO_HOME so the CLI can
    // resolve `<huitzo_home>/bin/uv` ABSOLUTELY (it survives the runner's env-scrub,
    // which forwards PATH but not HUITZO_HOME), and prepend `<huitzo_home>/bin` to PATH
    // so a bare `uv` also resolves for the CLI and its build subprocesses.
    //
    // SAFETY: This is called from main() before any threads are spawned for the exec
    // path (the background update thread is already detached and doesn't read these
    // variables). On Unix, execvp replaces the process immediately after this point, so
    // no concurrent access is possible.
    unsafe {
        std::env::set_var("HUITZO_MANAGED", "1");
        std::env::set_var("HUITZO_HOME", crate::dirs::huitzo_home());
        std::env::set_var("PATH", path_with_bin_dir_prepended());
    }

    #[cfg(unix)]
    {
        exec_unix(venv_python, &python_argv(args, safe_path))
    }

    #[cfg(windows)]
    {
        exec_windows(venv_python, &python_argv(args, safe_path))
    }
}

/// The interpreter arguments: `[-P] -m huitzo_cli <args…>`.
///
/// `-P` keeps the invocation directory off `sys.path` (#53): without it a
/// `huitzo_cli/` directory in the cwd shadows the interpreter's own installed
/// copy, mixing a source tree with a different environment's dependencies.
/// Mirrors the systemd unit fix in `Huitzo-Inc/cli#300`.
fn python_argv(args: &[String], safe_path: bool) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(args.len() + 3);
    if safe_path {
        argv.push("-P".to_string());
    }
    argv.push("-m".to_string());
    argv.push("huitzo_cli".to_string());
    argv.extend(args.iter().cloned());
    argv
}

/// The current `PATH` with `<huitzo_home>/bin` prepended (as a single front entry).
///
/// Prepending makes the launcher-bundled `uv` win over any older system uv, and the
/// runner's env-scrub forwards `PATH`, so the build subprocess inherits it too.
fn path_with_bin_dir_prepended() -> std::ffi::OsString {
    let bin = crate::dirs::bin_dir();
    match std::env::var_os("PATH") {
        Some(existing) => {
            let mut entries = vec![bin.clone()];
            // Drop any pre-existing copy of our bin dir so it stays a single front entry.
            entries.extend(std::env::split_paths(&existing).filter(|p| *p != bin));
            std::env::join_paths(entries).unwrap_or(existing)
        }
        None => bin.into_os_string(),
    }
}

#[cfg(unix)]
fn exec_unix(venv_python: &Path, args: &[String]) -> Result<(), Error> {
    use std::ffi::CString;

    let python_str = venv_python
        .to_str()
        .ok_or_else(|| Error::Exec("Python path contains invalid UTF-8".to_string()))?;

    let python =
        CString::new(python_str).map_err(|e| Error::Exec(format!("Invalid python path: {e}")))?;

    let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv.push(python.clone());
    for arg in args {
        argv.push(
            CString::new(arg.as_str())
                .map_err(|e| Error::Exec(format!("Invalid argument: {e}")))?,
        );
    }

    nix::unistd::execvp(&python, &argv).map_err(|e| Error::Exec(format!("execvp failed: {e}")))?;

    unreachable!()
}

#[cfg(windows)]
fn exec_windows(venv_python: &Path, args: &[String]) -> Result<(), Error> {
    use std::process::Command;

    let mut cmd = Command::new(venv_python);
    cmd.args(args);

    let status = cmd
        .status()
        .map_err(|e| Error::Exec(format!("Failed to spawn Python: {e}")))?;

    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_carries_dash_p_only_when_supported() {
        let args = vec!["pack".to_string(), "dev".to_string()];
        assert_eq!(
            python_argv(&args, true),
            vec!["-P", "-m", "huitzo_cli", "pack", "dev"]
        );
        // Python 3.10 rejects `-P` outright, so an interpreter we cannot
        // prove is 3.11+ is invoked without it.
        assert_eq!(
            python_argv(&args, false),
            vec!["-m", "huitzo_cli", "pack", "dev"]
        );
    }

    #[test]
    fn argv_preserves_user_arguments_verbatim() {
        let args = vec!["--flag=with space".to_string(), "-P".to_string()];
        let argv = python_argv(&args, true);
        // The module arguments come first; a user argument that happens to
        // look like an interpreter flag stays after `-m huitzo_cli`.
        assert_eq!(&argv[..3], &["-P", "-m", "huitzo_cli"]);
        assert_eq!(&argv[3..], &["--flag=with space", "-P"]);
    }
}
