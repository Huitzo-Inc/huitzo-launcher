use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dirs;
use crate::errors::Error;

const UPDATE_CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60; // 24 hours

/// Pending update staged for next launch.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingUpdate {
    /// "pip" for Python package, "launcher" for binary self-update.
    pub kind: String,
    /// Target version.
    pub version: String,
}

/// Launcher state persisted at `~/.huitzo/manifest.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub python_path: String,
    pub python_version: String,
    pub huitzo_version: String,
    pub launcher_version: String,
    pub last_update_check: u64,
    pub pending_update: Option<PendingUpdate>,
    pub created_at: u64,
    /// How huitzo was installed: "pypi" or "github_release".
    #[serde(default)]
    pub install_source: Option<String>,
    /// Platform tag for the installed wheel (e.g. "linux-x86_64").
    #[serde(default)]
    pub wheel_platform: Option<String>,
}

/// Load manifest from disk. Returns `None` if the file doesn't exist.
///
/// If the file exists but is corrupted, deletes it and returns `None`
/// (triggering a re-bootstrap).
pub fn load() -> Option<Manifest> {
    let path = dirs::manifest_path();
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<Manifest>(&content) {
        Ok(mut m) => {
            // Auto-migrate v1 → v2: add new fields with defaults
            if m.schema_version < 2 {
                m.schema_version = 2;
                if m.install_source.is_none() {
                    m.install_source = Some("pypi".to_string());
                }
                // Save migrated manifest (best-effort)
                let _ = save(&m);
            }
            Some(m)
        }
        Err(_) => {
            // Auto-repair: corrupted manifest triggers re-bootstrap
            let _ = std::fs::remove_file(&path);
            None
        }
    }
}

/// Save manifest to disk atomically (write to temp file, then rename).
pub fn save(manifest: &Manifest) -> Result<(), Error> {
    let path = dirs::manifest_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Manifest(format!("Failed to create directory: {e}")))?;
    }

    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| Error::Manifest(format!("Failed to serialize manifest: {e}")))?;

    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)
        .map_err(|e| Error::Manifest(format!("Failed to write manifest: {e}")))?;
    std::fs::rename(&tmp_path, &path)
        .map_err(|e| Error::Manifest(format!("Failed to rename manifest: {e}")))?;

    Ok(())
}

/// Check if the update check interval has elapsed.
pub fn needs_update_check(manifest: &Manifest) -> bool {
    let now = now_secs();
    now.saturating_sub(manifest.last_update_check) >= UPDATE_CHECK_INTERVAL_SECS
}

/// Current time as Unix timestamp in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trip() {
        let manifest = Manifest {
            schema_version: 2,
            python_path: "/usr/bin/python3.13".to_string(),
            python_version: "3.13".to_string(),
            huitzo_version: "0.1.7".to_string(),
            launcher_version: env!("CARGO_PKG_VERSION").to_string(),
            last_update_check: 0,
            pending_update: None,
            created_at: now_secs(),
            install_source: Some("github_release".to_string()),
            wheel_platform: Some("linux_x86_64".to_string()),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.huitzo_version, "0.1.7");
        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.install_source.as_deref(), Some("github_release"));
        assert_eq!(parsed.wheel_platform.as_deref(), Some("linux_x86_64"));
    }

    #[test]
    fn manifest_v1_compat() {
        // v1 manifests (no install_source/wheel_platform) should deserialize
        let json = r#"{
            "schema_version": 1,
            "python_path": "/usr/bin/python3.13",
            "python_version": "3.13",
            "huitzo_version": "0.1.0",
            "launcher_version": "0.1.0",
            "last_update_check": 0,
            "pending_update": null,
            "created_at": 0
        }"#;
        let parsed: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.schema_version, 1);
        assert!(parsed.install_source.is_none());
        assert!(parsed.wheel_platform.is_none());
    }

    #[test]
    fn needs_update_check_when_stale() {
        let manifest = Manifest {
            schema_version: 2,
            python_path: String::new(),
            python_version: String::new(),
            huitzo_version: String::new(),
            launcher_version: String::new(),
            last_update_check: 0, // epoch = always stale
            pending_update: None,
            created_at: 0,
            install_source: None,
            wheel_platform: None,
        };
        assert!(needs_update_check(&manifest));
    }

    #[test]
    fn no_update_check_when_fresh() {
        let manifest = Manifest {
            schema_version: 2,
            python_path: String::new(),
            python_version: String::new(),
            huitzo_version: String::new(),
            launcher_version: String::new(),
            last_update_check: now_secs(), // just checked
            pending_update: None,
            created_at: 0,
            install_source: None,
            wheel_platform: None,
        };
        assert!(!needs_update_check(&manifest));
    }
}
