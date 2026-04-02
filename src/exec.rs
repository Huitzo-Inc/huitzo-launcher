use std::path::Path;

use crate::errors::Error;

/// Replace the current process with the Python CLI.
///
/// On Unix, this uses `execvp()` — the launcher process is replaced entirely.
/// On Windows, this spawns a child process and propagates its exit code.
pub fn exec_into_python(venv_python: &Path, args: &[String]) -> Result<(), Error> {
    #[cfg(unix)]
    {
        exec_unix(venv_python, args)
    }

    #[cfg(windows)]
    {
        exec_windows(venv_python, args)
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

    let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 3);
    argv.push(python.clone());
    argv.push(CString::new("-m").unwrap());
    argv.push(CString::new("huitzo_cli").unwrap());
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
    cmd.args(["-m", "huitzo_cli"]);
    cmd.args(args);

    let status = cmd
        .status()
        .map_err(|e| Error::Exec(format!("Failed to spawn Python: {e}")))?;

    std::process::exit(status.code().unwrap_or(1));
}
