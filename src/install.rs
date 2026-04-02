use std::process::Command;

use crate::dirs;
use crate::errors::Error;

/// Install or upgrade a package in the managed venv via pip.
///
/// If `index_url` is provided (e.g. for TestPyPI), it is passed as `--index-url`.
pub fn install_package(package: &str, index_url: Option<&str>) -> Result<(), Error> {
    let python = dirs::venv_python();
    let mut cmd = Command::new(&python);
    cmd.args(["-m", "pip", "install", "--upgrade", "--quiet", package]);

    if let Some(url) = index_url {
        cmd.args(["--index-url", url]);
    }

    let output = cmd
        .output()
        .map_err(|e| Error::PipInstall(format!("Failed to run pip: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::PipInstall(stderr.to_string()));
    }

    Ok(())
}

/// Get the installed version of a package in the managed venv.
///
/// Returns `None` if the package is not installed.
pub fn get_installed_version(package: &str) -> Result<Option<String>, Error> {
    let python = dirs::venv_python();
    let script = format!(
        "from importlib.metadata import version, PackageNotFoundError\n\
         try:\n\
         \x20   print(version('{package}'))\n\
         except PackageNotFoundError:\n\
         \x20   pass"
    );

    let output = Command::new(&python)
        .args(["-c", &script])
        .output()
        .map_err(|e| Error::PipInstall(format!("Failed to query package version: {e}")))?;

    if !output.status.success() {
        return Ok(None);
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        Ok(None)
    } else {
        Ok(Some(version))
    }
}
