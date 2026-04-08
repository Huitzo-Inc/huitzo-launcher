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

/// Discover all Python 3.11+ interpreters on PATH.
///
/// Scans candidates in order, runs each to extract its version, and returns
/// all that meet the minimum version requirement. The caller should iterate
/// these and try each one (e.g., for venv creation) since some interpreters
/// may be broken or incomplete (e.g., RC builds missing ensurepip).
pub fn discover_all() -> Result<Vec<PythonInfo>, Error> {
    let mut found = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();

    for candidate in CANDIDATES {
        // Use which_all to find ALL instances of each candidate in PATH,
        // not just the first. This handles cases where uv/pyenv-managed
        // Pythons shadow system Pythons in PATH order.
        if let Ok(paths) = which::which_all(candidate) {
            for path in paths {
                // Deduplicate by canonical path
                let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
                if !seen_paths.insert(canonical) {
                    continue;
                }
                if let Some(info) = probe_version(&path) {
                    if info.version.0 >= MIN_MAJOR && info.version.1 >= MIN_MINOR {
                        found.push(info);
                    }
                }
            }
        }
    }
    if found.is_empty() {
        Err(Error::NoPython)
    } else {
        Ok(found)
    }
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
    fn discover_all_returns_qualifying_candidates() {
        // If Python 3.11+ is available on this system, discover_all should return at least one
        if let Ok(candidates) = discover_all() {
            assert!(!candidates.is_empty());
            for info in &candidates {
                assert!(info.version.0 >= 3);
                assert!(info.version.1 >= 11);
                assert!(info.path.exists());
            }
        }
    }
}
