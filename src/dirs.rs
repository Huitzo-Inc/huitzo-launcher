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

/// Returns the launcher-managed bin directory: `<huitzo_home>/bin/`.
///
/// Holds the launcher binary itself and (huitzo#965 / task #38) the bundled `uv`. This
/// directory is prepended to `PATH` before exec so the CLI + its build subprocesses can
/// resolve `uv`.
pub fn bin_dir() -> PathBuf {
    huitzo_home().join("bin")
}

/// Returns the staged uv binary path: `<huitzo_home>/bin/uv` (`uv.exe` on Windows).
pub fn uv_bin() -> PathBuf {
    let name = if cfg!(windows) { "uv.exe" } else { "uv" };
    bin_dir().join(name)
}

/// Returns the uv version-stamp file: `<huitzo_home>/uv-version.txt`.
///
/// Records which pinned uv version is currently staged so a launch can short-circuit
/// the download when uv is already current (idempotency).
pub fn uv_version_stamp() -> PathBuf {
    huitzo_home().join("uv-version.txt")
}

/// Returns the user's home directory, panicking if unavailable.
pub fn home_dir_or_panic() -> PathBuf {
    dirs::home_dir().expect("Cannot determine home directory")
}

/// Returns the deployment SDK staging root: `<huitzo_home>/sdk/`.
///
/// Per-deployment trees live underneath as `sdk/<host>/<version>/`.
pub fn sdk_dir() -> PathBuf {
    huitzo_home().join("sdk")
}

/// Returns the deployment extension wheel staging root: `<huitzo_home>/ext/`.
///
/// Per-deployment trees live underneath as `ext/<host>/<name>/<version>/`.
pub fn ext_dir() -> PathBuf {
    huitzo_home().join("ext")
}

/// Returns the TOFU pinned-key directory: `<huitzo_home>/trust/`.
///
/// Per-deployment trust artefacts live here as `<host>.pubkey` (raw 32
/// bytes Ed25519) plus `<host>.json` (fingerprint + first-seen metadata).
pub fn trust_dir() -> PathBuf {
    huitzo_home().join("trust")
}

/// Returns the pinned-key path for a given deployment host.
pub fn pinned_key_path(host: &str) -> PathBuf {
    trust_dir().join(format!("{host}.pubkey"))
}

/// Returns the trust metadata sidecar path for a given deployment host.
pub fn trust_meta_path(host: &str) -> PathBuf {
    trust_dir().join(format!("{host}.json"))
}

/// Returns the path to the capability-refresh marker file written by the
/// Python CLI after `huitzo config set api_url` or `huitzo login`.
pub fn capability_refresh_marker() -> PathBuf {
    huitzo_home().join(".needs-capability-refresh")
}

/// Returns the lockfile path used to serialize concurrent capability /
/// bundle refreshes.
#[allow(dead_code)] // Wired in a follow-up; reserved for the flock guard.
pub fn capability_lock_path() -> PathBuf {
    huitzo_home().join(".capability.lock")
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

    #[test]
    fn trust_paths_are_host_scoped() {
        unsafe { std::env::set_var("HUITZO_HOME", "/tmp/test-huitzo-trust") };
        assert_eq!(
            pinned_key_path("huitzo.ai"),
            PathBuf::from("/tmp/test-huitzo-trust/trust/huitzo.ai.pubkey")
        );
        assert_eq!(
            trust_meta_path("staging.huitzo.ai"),
            PathBuf::from("/tmp/test-huitzo-trust/trust/staging.huitzo.ai.json")
        );
        assert_eq!(sdk_dir(), PathBuf::from("/tmp/test-huitzo-trust/sdk"));
        assert_eq!(ext_dir(), PathBuf::from("/tmp/test-huitzo-trust/ext"));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
