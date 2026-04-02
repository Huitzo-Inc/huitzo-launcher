use std::path::PathBuf;

/// Returns the Huitzo home directory: `$HUITZO_HOME` or `~/.huitzo/`.
pub fn huitzo_home() -> PathBuf {
    if let Ok(val) = std::env::var("HUITZO_HOME") {
        return PathBuf::from(val);
    }
    dirs::home_dir()
        .expect("Cannot determine home directory")
        .join(".huitzo")
}

/// Returns the managed venv directory: `<huitzo_home>/venv/`.
pub fn venv_dir() -> PathBuf {
    huitzo_home().join("venv")
}

/// Returns the path to the Python binary inside the managed venv.
pub fn venv_python() -> PathBuf {
    let venv = venv_dir();
    if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    }
}

/// Returns the path to `manifest.json`.
pub fn manifest_path() -> PathBuf {
    huitzo_home().join("manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huitzo_home_respects_env_override() {
        // SAFETY: test runs single-threaded via cargo test -- --test-threads=1
        unsafe { std::env::set_var("HUITZO_HOME", "/tmp/test-huitzo-home") };
        assert_eq!(huitzo_home(), PathBuf::from("/tmp/test-huitzo-home"));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn venv_python_path_is_under_venv() {
        unsafe { std::env::set_var("HUITZO_HOME", "/tmp/test-huitzo-dirs") };
        let python = venv_python();
        assert!(python.starts_with("/tmp/test-huitzo-dirs/venv"));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
