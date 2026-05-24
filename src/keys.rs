//! TOFU (Trust On First Use) deployment-key pinning.
//!
//! On the first capability fetch against a deployment, the launcher stores
//! the advertised Ed25519 public key under `~/.huitzo/trust/<host>.pubkey`
//! (raw 32 bytes) along with a JSON sidecar at `~/.huitzo/trust/<host>.json`
//! containing `{fingerprint, first_seen, issuer}`.
//!
//! On subsequent fetches the stored key is loaded and compared against the
//! advertised key. A mismatch is a `TrustViolation` — the launcher refuses
//! to install the bundle unless the operator explicitly re-pins with
//! `huitzo --launcher-trust-rotate`.
//!
//! ## Scope (v1)
//!
//! This module implements only the **emergency** `--launcher-trust-rotate`
//! escape hatch. Routine overlap-window rotation (capability response
//! carrying a `next_public_key` field signed by the current key for a
//! 30-day handoff) is **explicitly deferred** to a follow-up issue filed
//! during Wave 3 coda of epic #583. See
//! `docs/architecture/security/extension-signing.md` "Routine rotation"
//! section.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dirs;
use crate::errors::Error;

/// Sidecar metadata persisted alongside the pinned raw-pubkey file.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustMetadata {
    /// `SHA256:` + colon-grouped hex fingerprint, matching the RFC UX.
    pub fingerprint: String,
    /// ISO-8601 UTC timestamp of first-seen.
    pub first_seen: String,
    /// Deployment / issuer host as advertised in the capability response.
    pub issuer: String,
}

/// A pinned key + its metadata, ready for verification.
#[derive(Debug)]
pub struct PinnedKey {
    #[allow(dead_code)] // Surfaced via tests + diagnostic output.
    pub host: String,
    pub key: VerifyingKey,
    pub metadata: TrustMetadata,
}

/// Decode a base64-encoded Ed25519 public key (32 bytes) into a `VerifyingKey`.
pub fn decode_pubkey(b64: &str) -> Result<VerifyingKey, Error> {
    let raw = BASE64.decode(b64.trim()).map_err(|e| Error::BundleVerify {
        reason: format!("public key is not valid base64: {e}"),
    })?;
    if raw.len() != 32 {
        return Err(Error::BundleVerify {
            reason: format!("public key must be 32 bytes, got {}", raw.len()),
        });
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&buf).map_err(|e| Error::BundleVerify {
        reason: format!("public key is not a valid Ed25519 point: {e}"),
    })
}

/// Compute the human-facing fingerprint for a public key.
///
/// Format: `SHA256:` followed by the SHA-256 of the raw 32 bytes, rendered
/// as five colon-separated 4-hex-digit groups (truncated to 16 bytes / 32
/// hex chars). Matches the security RFC UX.
pub fn fingerprint(key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    // Group as 4-char chunks separated by ':' for readability.
    let groups: Vec<String> = (0..hex.len())
        .step_by(4)
        .map(|i| hex[i..(i + 4).min(hex.len())].to_string())
        .collect();
    format!("SHA256:{}", groups.join(":"))
}

/// Load the pinned key for `host`, if any.
///
/// Returns `None` if no `<host>.pubkey` file exists (= first-use case).
/// Returns an error only if the file is present but unreadable or
/// structurally invalid.
pub fn load_pinned(host: &str) -> Result<Option<PinnedKey>, Error> {
    let key_path = dirs::pinned_key_path(host);
    if !key_path.exists() {
        return Ok(None);
    }

    let raw = fs::read(&key_path).map_err(|e| {
        Error::Manifest(format!(
            "failed to read pinned key {}: {e}",
            key_path.display()
        ))
    })?;
    if raw.len() != 32 {
        return Err(Error::BundleVerify {
            reason: format!(
                "pinned key {} is corrupt: expected 32 bytes, got {}",
                key_path.display(),
                raw.len()
            ),
        });
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&raw);
    let key = VerifyingKey::from_bytes(&buf).map_err(|e| Error::BundleVerify {
        reason: format!(
            "pinned key {} is not a valid Ed25519 point: {e}",
            key_path.display()
        ),
    })?;

    let meta_path = dirs::trust_meta_path(host);
    let metadata = if meta_path.exists() {
        let s = fs::read_to_string(&meta_path)
            .map_err(|e| Error::Manifest(format!("failed to read trust metadata: {e}")))?;
        serde_json::from_str(&s).map_err(|e| {
            Error::Manifest(format!(
                "trust metadata at {} is corrupt: {e}",
                meta_path.display()
            ))
        })?
    } else {
        // Metadata sidecar was deleted; reconstruct what we can from the key.
        TrustMetadata {
            fingerprint: fingerprint(&key),
            first_seen: now_iso8601(),
            issuer: host.to_string(),
        }
    };

    Ok(Some(PinnedKey {
        host: host.to_string(),
        key,
        metadata,
    }))
}

/// Pin `key` for `host`, writing the raw pubkey + metadata sidecar atomically.
///
/// Existing trust files for the host are overwritten. The caller is
/// responsible for deciding whether the overwrite is legitimate (first-use
/// TOFU, or operator-confirmed rotation via `--launcher-trust-rotate`).
pub fn pin(host: &str, key: &VerifyingKey) -> Result<PinnedKey, Error> {
    let trust_dir = dirs::trust_dir();
    fs::create_dir_all(&trust_dir).map_err(|e| {
        Error::Manifest(format!(
            "failed to create trust dir {}: {e}",
            trust_dir.display()
        ))
    })?;

    let key_path = dirs::pinned_key_path(host);
    write_atomic(&key_path, key.as_bytes())?;
    restrict_permissions(&key_path)?;

    let metadata = TrustMetadata {
        fingerprint: fingerprint(key),
        first_seen: now_iso8601(),
        issuer: host.to_string(),
    };
    let meta_path = dirs::trust_meta_path(host);
    let meta_json = serde_json::to_vec_pretty(&metadata)
        .map_err(|e| Error::Manifest(format!("failed to serialize trust metadata: {e}")))?;
    write_atomic(&meta_path, &meta_json)?;
    restrict_permissions(&meta_path)?;

    Ok(PinnedKey {
        host: host.to_string(),
        key: *key,
        metadata,
    })
}

/// First-use pin (TOFU): if no key is stored for `host`, pin `advertised`
/// and emit the "Pinning new signing key" notice. If a key already exists
/// and matches, return it. On mismatch return a `TrustViolation`.
///
/// `force_rotate` short-circuits the mismatch check — pass `true` only
/// when the operator has explicitly opted in via `--launcher-trust-rotate`.
pub fn pin_or_load(
    host: &str,
    advertised: &VerifyingKey,
    force_rotate: bool,
) -> Result<PinnedKey, Error> {
    match load_pinned(host)? {
        None => {
            eprintln!("Pinning new signing key for {host}");
            let pinned = pin(host, advertised)?;
            eprintln!("  fingerprint: {}", pinned.metadata.fingerprint);
            Ok(pinned)
        }
        Some(existing) => {
            if existing.key.as_bytes() == advertised.as_bytes() {
                return Ok(existing);
            }
            if force_rotate {
                eprintln!("Rotating pinned signing key for {host} (--launcher-trust-rotate)");
                eprintln!("  previous fingerprint: {}", existing.metadata.fingerprint);
                let new_pin = pin(host, advertised)?;
                eprintln!("  new fingerprint:      {}", new_pin.metadata.fingerprint);
                return Ok(new_pin);
            }
            Err(Error::TrustViolation {
                stored: existing.metadata.fingerprint,
                advertised: fingerprint(advertised),
            })
        }
    }
}

/// Extract the canonical host (`example.com` or `example.com:8443`) from a
/// deployment URL. Used to scope trust artefacts on disk.
pub fn canonical_host(api_url: &str) -> Result<String, Error> {
    let parsed = url::Url::parse(api_url)
        .map_err(|e| Error::Manifest(format!("invalid deployment URL '{api_url}': {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Manifest(format!("deployment URL '{api_url}' has no host")))?;
    let needs_port = match (parsed.scheme(), parsed.port()) {
        ("https", Some(443)) | ("http", Some(80)) => false,
        (_, Some(_)) => true,
        (_, None) => false,
    };
    if needs_port {
        if let Some(port) = parsed.port() {
            return Ok(format!("{host}:{port}"));
        }
    }
    Ok(host.to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp)
        .map_err(|e| Error::Manifest(format!("failed to create {}: {e}", tmp.display())))?;
    file.write_all(bytes)
        .map_err(|e| Error::Manifest(format!("failed to write {}: {e}", tmp.display())))?;
    file.sync_all().ok();
    drop(file);
    fs::rename(&tmp, path).map_err(|e| {
        Error::Manifest(format!(
            "failed to rename {} → {}: {e}",
            tmp.display(),
            path.display()
        ))
    })
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
        .map_err(|e| Error::Manifest(format!("failed to chmod {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), Error> {
    // Best-effort: no POSIX permissions on non-Unix. The trust file is
    // still scoped to the user's home, which is the primary boundary.
    Ok(())
}

fn now_iso8601() -> String {
    // Avoid pulling in chrono just for one timestamp; format the Unix
    // epoch seconds into a minimal "YYYY-MM-DDTHH:MM:SSZ" string via the
    // shared seconds-to-date trick. For trust-file metadata exactness
    // matters less than monotonic ordering, so we accept ~1 s of skew.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format_unix_iso8601(secs)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (no leap-second handling).
fn format_unix_iso8601(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hour = (time_of_day / 3600) as u32;
    let minute = ((time_of_day % 3600) / 60) as u32;
    let second = (time_of_day % 60) as u32;

    // Civil-from-days algorithm (Howard Hinnant), epoch = 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // HUITZO_HOME is process-global; serialize tests that mutate it so
    // parallel runners don't stomp on each other's tempdirs.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct HomeGuard {
        _dir: TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn temp_home() -> HomeGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", dir.path()) };
        HomeGuard {
            _dir: dir,
            _lock: lock,
        }
    }

    fn make_key() -> VerifyingKey {
        SigningKey::generate(&mut OsRng).verifying_key()
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let key = make_key();
        let fp = fingerprint(&key);
        assert!(fp.starts_with("SHA256:"));
        // 16 bytes → 32 hex chars → 8 groups of 4 chars.
        let groups: Vec<&str> = fp.trim_start_matches("SHA256:").split(':').collect();
        assert_eq!(groups.len(), 8);
        for g in groups {
            assert_eq!(g.len(), 4);
        }
    }

    #[test]
    fn decode_pubkey_rejects_wrong_length() {
        let bad = BASE64.encode(b"short");
        assert!(decode_pubkey(&bad).is_err());
    }

    #[test]
    fn pin_or_load_first_use_writes_files() {
        let _home = temp_home();
        let key = make_key();
        let pinned = pin_or_load("test.example", &key, false).unwrap();
        assert_eq!(pinned.metadata.issuer, "test.example");
        assert!(dirs::pinned_key_path("test.example").exists());
        assert!(dirs::trust_meta_path("test.example").exists());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn pin_or_load_returns_existing_on_match() {
        let _home = temp_home();
        let key = make_key();
        let first = pin_or_load("test.example", &key, false).unwrap();
        let second = pin_or_load("test.example", &key, false).unwrap();
        assert_eq!(first.metadata.first_seen, second.metadata.first_seen);
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn pin_or_load_rejects_mismatch() {
        let _home = temp_home();
        let original = make_key();
        let _ = pin_or_load("test.example", &original, false).unwrap();
        let attacker = make_key();
        let err = pin_or_load("test.example", &attacker, false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn pin_or_load_force_rotate_overwrites() {
        let _home = temp_home();
        let original = make_key();
        let _ = pin_or_load("test.example", &original, false).unwrap();
        let new_key = make_key();
        let rotated = pin_or_load("test.example", &new_key, true).unwrap();
        assert_eq!(rotated.key.as_bytes(), new_key.as_bytes());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn canonical_host_strips_default_ports() {
        assert_eq!(canonical_host("https://huitzo.ai").unwrap(), "huitzo.ai");
        assert_eq!(
            canonical_host("https://huitzo.ai:443").unwrap(),
            "huitzo.ai"
        );
        assert_eq!(
            canonical_host("https://staging.huitzo.ai:8443").unwrap(),
            "staging.huitzo.ai:8443"
        );
    }

    #[test]
    fn format_unix_iso8601_handles_epoch() {
        assert_eq!(format_unix_iso8601(0), "1970-01-01T00:00:00Z");
        // 2026-05-23T00:00:00Z is 1_779_926_400 unix seconds.
        let s = format_unix_iso8601(1_779_926_400);
        assert!(s.starts_with("2026-"));
    }
}
