// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! The managed virtual environment at `<huitzo_home>/venv`.
//!
//! Built by `uv venv`, never by `python -m venv` (D1). Debian and Ubuntu split
//! `ensurepip` into a separate `python3.N-venv` package, so `python -m venv`
//! fails outright on a stock `apt install python3` host (#B3); `uv venv` writes
//! the environment itself and needs no such package.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::dirs;
use crate::errors::Error;
use crate::uv;

/// Check if the managed venv is healthy.
///
/// A venv is healthy if:
/// 1. The Python binary exists and is a file
/// 2. pyvenv.cfg exists
/// 3. `import huitzo_cli` succeeds
pub fn is_healthy() -> bool {
    let python = dirs::venv_python();
    let pyvenv_cfg = dirs::venv_dir().join("pyvenv.cfg");

    if !python.is_file() || !pyvenv_cfg.is_file() {
        return false;
    }

    // Verify huitzo_cli is importable
    Command::new(&python)
        .args(["-c", "import huitzo_cli"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Create the managed venv with `uv venv --python <spec>`.
///
/// `python_spec` is anything `uv` accepts for `--python`: an absolute path to a
/// discovered system interpreter, or a bare version like `3.13` resolving to a
/// uv-managed CPython.
///
/// `--seed` installs `pip` into the new environment. The launcher installs the
/// CLI wheel with `python -m pip` (see `install.rs`), and a `uv venv` is empty
/// by default, so seeding is what keeps that install path working.
///
/// Any partial environment is removed before the error is returned, so the
/// caller can try the next interpreter against a clean directory.
pub fn create(uv_bin: &Path, python_spec: &OsStr) -> Result<(), Error> {
    let venv_dir = dirs::venv_dir();
    let interpreter = python_spec.to_string_lossy().to_string();

    let output = uv::command(uv_bin)
        .arg("venv")
        .arg("--python")
        .arg(python_spec)
        .arg("--seed")
        .arg(&venv_dir)
        .output()
        .map_err(|e| Error::VenvCreate {
            interpreter: interpreter.clone(),
            detail: format!("could not run {}: {e}", uv_bin.display()),
        })?;

    if !output.status.success() {
        // Clean up partial venv on failure
        let _ = std::fs::remove_dir_all(&venv_dir);
        return Err(Error::VenvCreate {
            interpreter,
            detail: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(())
}

/// Remove the managed venv directory entirely.
pub fn destroy() -> Result<(), Error> {
    let venv_dir = dirs::venv_dir();
    if venv_dir.exists() {
        std::fs::remove_dir_all(&venv_dir)
            .map_err(|e| Error::VenvRemove(format!("{}: {e}", venv_dir.display())))?;
    }
    Ok(())
}

/// The interpreter the managed venv was built from, read out of `pyvenv.cfg`.
///
/// The honest answer to "which Python is the managed environment running",
/// including for a uv-provisioned CPython whose path the launcher never typed
/// out itself.
pub fn base_interpreter() -> Option<PathBuf> {
    let cfg = std::fs::read_to_string(dirs::venv_dir().join("pyvenv.cfg")).ok()?;
    resolve_base_interpreter(&cfg, |p| p.is_file())
}

/// Resolve the base interpreter from a `pyvenv.cfg` body.
///
/// `base-executable` when present (CPython 3.11+ writes it). `uv venv` does not,
/// so fall back to the `home` directory plus the interpreter name `version_info`
/// implies — probed through `exists` so a name that is not actually there is
/// never reported as the answer.
fn resolve_base_interpreter(cfg: &str, exists: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    if let Some(exe) = cfg_value(cfg, "base-executable") {
        return Some(PathBuf::from(exe));
    }
    let home = PathBuf::from(cfg_value(cfg, "home")?);

    let mut names: Vec<String> = Vec::new();
    if let Some(version) = cfg_value(cfg, "version_info") {
        let mut parts = version.split('.');
        if let (Some(major), Some(minor)) = (parts.next(), parts.next()) {
            names.push(exe_name(&format!("python{major}.{minor}")));
        }
    }
    names.push(exe_name("python3"));
    names.push(exe_name("python"));

    names.into_iter().map(|n| home.join(n)).find(|p| exists(p))
}

/// Platform-correct executable file name.
fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

/// Read a `key = value` entry out of a `pyvenv.cfg` body.
fn cfg_value(cfg: &str, key: &str) -> Option<String> {
    for line in cfg.lines() {
        let Some((k, value)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `pyvenv.cfg` `uv venv 0.8.17` writes — no `base-executable`.
    const UV_CFG: &str = "home = /home/u/.huitzo/python/cpython-3.13.7-linux-x86_64-gnu/bin\n\
                          implementation = CPython\n\
                          uv = 0.8.17\n\
                          version_info = 3.13.7\n\
                          include-system-site-packages = false\n\
                          seed = true\n";

    #[test]
    fn base_executable_is_used_when_present() {
        let cfg = "home = /usr/bin\n\
                   version_info = 3.12.3\n\
                   base-executable = /usr/bin/python3.12\n";
        assert_eq!(
            resolve_base_interpreter(cfg, |_| true),
            Some(PathBuf::from("/usr/bin/python3.12"))
        );
    }

    #[test]
    fn uv_cfg_falls_back_to_home_plus_version_info() {
        let want = PathBuf::from(exe_name(
            "/home/u/.huitzo/python/cpython-3.13.7-linux-x86_64-gnu/bin/python3.13",
        ));
        assert_eq!(
            resolve_base_interpreter(UV_CFG, |p| p == want),
            Some(want.clone())
        );
    }

    #[test]
    fn fallback_only_reports_a_name_that_actually_exists() {
        // `python3.13` absent, `python3` present — the answer must be the one on
        // disk, not the first name we guessed.
        let want = PathBuf::from(exe_name(
            "/home/u/.huitzo/python/cpython-3.13.7-linux-x86_64-gnu/bin/python3",
        ));
        assert_eq!(
            resolve_base_interpreter(UV_CFG, |p| p == want),
            Some(want.clone())
        );
        // Nothing on disk at all: "unknown" must be distinguishable from a guess.
        assert_eq!(resolve_base_interpreter(UV_CFG, |_| false), None);
    }

    #[test]
    fn a_cfg_without_home_is_none() {
        assert_eq!(
            resolve_base_interpreter("include-system-site-packages = false\n", |_| true),
            None
        );
    }
}
