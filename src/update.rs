use crate::manifest::{self, PendingUpdate};

/// PyPI JSON API URL for the huitzo package.
const PYPI_URL: &str = "https://pypi.org/pypi/huitzo/json";

/// Check if update checking is disabled via environment variable.
pub fn should_skip() -> bool {
    std::env::var("HUITZO_SKIP_UPDATE_CHECK")
        .is_ok_and(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
}

/// Background update check: queries PyPI for a newer huitzo version.
///
/// Updates the manifest with the check timestamp and any pending update.
/// Errors are silently ignored (non-blocking).
pub fn background_check() {
    let Some(mut m) = manifest::load() else {
        return;
    };

    // Check PyPI for newer Python package
    if let Some(latest) = check_pypi_version() {
        if version_is_newer(&latest, &m.huitzo_version) {
            eprintln!(
                "huitzo {latest} is available (installed: {}). \
                 Run 'huitzo --launcher-bootstrap' to update.",
                m.huitzo_version
            );
            m.pending_update = Some(PendingUpdate {
                kind: "pip".to_string(),
                version: latest,
            });
        }
    }

    m.last_update_check = manifest::now_secs();
    let _ = manifest::save(&m);
}

/// Query PyPI JSON API for the latest version of the huitzo package.
fn check_pypi_version() -> Option<String> {
    let mut response = ureq::get(PYPI_URL)
        .call()
        .ok()?;

    let body_str = response
        .body_mut()
        .read_to_string()
        .ok()?;

    let body: serde_json::Value = serde_json::from_str(&body_str).ok()?;

    body["info"]["version"]
        .as_str()
        .map(|s: &str| s.to_string())
}

/// Simple version comparison: "0.2.0" > "0.1.7".
///
/// Compares numeric segments left-to-right.
fn version_is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    let l = parse(latest);
    let c = parse(current);
    l > c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(version_is_newer("0.2.0", "0.1.7"));
        assert!(version_is_newer("1.0.0", "0.99.99"));
        assert!(!version_is_newer("0.1.7", "0.1.7"));
        assert!(!version_is_newer("0.1.6", "0.1.7"));
    }
}
