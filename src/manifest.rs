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

/// Cached capability-document state for the active deployment.
///
/// Schema v3+ only. Persisted so the launcher can skip the network on
/// subsequent invocations and still know which SDK + extension versions
/// are staged on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilityCache {
    /// Deployment host (e.g. `huitzo.ai`).
    pub deployment: String,
    /// SDK version currently staged under `~/.huitzo/sdk/<host>/<version>/`.
    pub sdk_version: String,
    /// Bundle sha256 (hex) — primary integrity anchor.
    pub bundle_sha256: String,
    /// ISO-8601 issued_at from the capability response.
    pub issued_at: String,
    /// Unix timestamp of the last successful refresh.
    pub last_refreshed: u64,
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
    /// v3+: host of the deployment whose bundle is currently active.
    #[serde(default)]
    pub active_deployment: Option<String>,
    /// v3+: cached capability document for the active deployment.
    #[serde(default)]
    pub capability_cache: Option<CapabilityCache>,
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
            let pre_migration = m.schema_version;
            // v1 → v2: install_source/wheel_platform defaulted in.
            if m.schema_version < 2 {
                m.schema_version = 2;
                if m.install_source.is_none() {
                    m.install_source = Some("pypi".to_string());
                }
            }
            // v2 → v3: active_deployment / capability_cache default to None;
            // bump the schema marker so future readers can rely on the new
            // fields existing structurally even when still empty.
            if m.schema_version < 3 {
                m.schema_version = 3;
            }
            if m.schema_version != pre_migration {
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
            schema_version: 3,
            python_path: "/usr/bin/python3.13".to_string(),
            python_version: "3.13".to_string(),
            huitzo_version: "0.1.7".to_string(),
            launcher_version: env!("CARGO_PKG_VERSION").to_string(),
            last_update_check: 0,
            pending_update: None,
            created_at: now_secs(),
            install_source: Some("github_release".to_string()),
            wheel_platform: Some("linux_x86_64".to_string()),
            active_deployment: Some("huitzo.ai".to_string()),
            capability_cache: Some(CapabilityCache {
                deployment: "huitzo.ai".to_string(),
                sdk_version: "0.5.2".to_string(),
                bundle_sha256: "abc".to_string(),
                issued_at: "2026-05-23T20:00:00Z".to_string(),
                last_refreshed: 0,
            }),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.huitzo_version, "0.1.7");
        assert_eq!(parsed.schema_version, 3);
        assert_eq!(parsed.install_source.as_deref(), Some("github_release"));
        assert_eq!(parsed.wheel_platform.as_deref(), Some("linux_x86_64"));
        assert_eq!(parsed.active_deployment.as_deref(), Some("huitzo.ai"));
        assert_eq!(
            parsed
                .capability_cache
                .as_ref()
                .map(|c| c.sdk_version.as_str()),
            Some("0.5.2")
        );
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
        assert!(parsed.active_deployment.is_none());
        assert!(parsed.capability_cache.is_none());
    }

    #[test]
    fn manifest_v2_compat_loads_with_no_capability_fields() {
        let json = r#"{
            "schema_version": 2,
            "python_path": "/usr/bin/python3.13",
            "python_version": "3.13",
            "huitzo_version": "0.2.0",
            "launcher_version": "0.2.7",
            "last_update_check": 0,
            "pending_update": null,
            "created_at": 0,
            "install_source": "github_release",
            "wheel_platform": "linux-x86_64"
        }"#;
        let parsed: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.schema_version, 2);
        assert!(parsed.active_deployment.is_none());
        assert!(parsed.capability_cache.is_none());
    }

    #[test]
    fn needs_update_check_when_stale() {
        let manifest = Manifest {
            schema_version: 3,
            python_path: String::new(),
            python_version: String::new(),
            huitzo_version: String::new(),
            launcher_version: String::new(),
            last_update_check: 0, // epoch = always stale
            pending_update: None,
            created_at: 0,
            install_source: None,
            wheel_platform: None,
            active_deployment: None,
            capability_cache: None,
        };
        assert!(needs_update_check(&manifest));
    }

    #[test]
    fn no_update_check_when_fresh() {
        let manifest = Manifest {
            schema_version: 3,
            python_path: String::new(),
            python_version: String::new(),
            huitzo_version: String::new(),
            launcher_version: String::new(),
            last_update_check: now_secs(), // just checked
            pending_update: None,
            created_at: 0,
            install_source: None,
            wheel_platform: None,
            active_deployment: None,
            capability_cache: None,
        };
        assert!(!needs_update_check(&manifest));
    }
}
