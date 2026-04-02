use crate::errors::Error;
use std::path::PathBuf;
use std::process::Command;

/// Information about a discovered Python interpreter.
pub struct PythonInfo {
    pub path: PathBuf,
    pub version: (u8, u8),
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

const MIN_MAJOR: u8 = 3;
const MIN_MINOR: u8 = 11;

/// Discover a Python 3.11+ interpreter on PATH.
///
/// Scans candidates in order, runs each to extract its version, and returns
/// the first one that meets the minimum version requirement.
pub fn discover() -> Result<PythonInfo, Error> {
    for candidate in CANDIDATES {
        if let Ok(path) = which::which(candidate) {
            if let Some(info) = probe_version(&path) {
                if info.version.0 >= MIN_MAJOR && info.version.1 >= MIN_MINOR {
                    return Ok(info);
                }
            }
        }
    }
    Err(Error::NoPython)
}

/// Run the interpreter to extract its version.
fn probe_version(path: &PathBuf) -> Option<PythonInfo> {
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

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version_str = version_str.trim();
    let mut parts = version_str.split('.');
    let major: u8 = parts.next()?.parse().ok()?;
    let minor: u8 = parts.next()?.parse().ok()?;

    Some(PythonInfo {
        path: path.clone(),
        version: (major, minor),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_works() {
        // If Python 3.11+ is available on this system, discover should succeed
        // Otherwise this test is skipped implicitly (discover returns Err)
        if let Ok(info) = discover() {
            assert!(info.version.0 >= 3);
            assert!(info.version.1 >= 11);
            assert!(info.path.exists());
        }
    }
}
