use std::path::Path;
use std::process::Command;

use crate::dirs;
use crate::errors::Error;

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

/// Create a new virtual environment using the given Python interpreter.
pub fn create(python_path: &Path) -> Result<(), Error> {
    let venv_dir = dirs::venv_dir();

    let output = Command::new(python_path)
        .args(["-m", "venv", &venv_dir.to_string_lossy()])
        .output()
        .map_err(|e| Error::VenvCreate(format!("Failed to run python -m venv: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Clean up partial venv on failure
        let _ = std::fs::remove_dir_all(&venv_dir);
        return Err(Error::VenvCreate(stderr.to_string()));
    }

    Ok(())
}

/// Remove the managed venv directory entirely.
pub fn destroy() -> Result<(), Error> {
    let venv_dir = dirs::venv_dir();
    if venv_dir.exists() {
        std::fs::remove_dir_all(&venv_dir)
            .map_err(|e| Error::VenvCreate(format!("Failed to remove venv: {e}")))?;
    }
    Ok(())
}
