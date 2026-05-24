//! SDK bundle download + verify + extract.
//!
//! The deployment bundle is a signed `.tar.zst` envelope (ADR-001)
//! containing:
//!   - `bundle-manifest.json` — signed by the deployment root key.
//!   - `extensions/*.whl` — wheel files for each published extension.
//!   - `signatures/bundle-manifest.sig` — Ed25519 sig over the manifest.
//!   - `signatures/extensions/<wheel>.sig` — per-wheel Ed25519 sig from
//!     the wheel's declared publisher.
//!
//! Verification order matches ADR-001:
//!   1. Bundle SHA-256 matches the capability advertisement.
//!   2. Bundle signature (over raw bytes) verifies against the pinned
//!      deployment-root key.
//!   3. Manifest signature verifies against the deployment-root key.
//!   4. Each publisher pubkey listed in the manifest is itself signed
//!      by the deployment root (`pubkey_sig`).
//!   5. Each extension's `.whl.sig` verifies against its publisher's
//!      pubkey and the wheel's recomputed SHA-256 matches.
//!
//! Any failure aborts the entire install — no partial trust.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capabilities::CapabilityDoc;
use crate::dirs;
use crate::download;
use crate::errors::Error;

/// `bundle-manifest.json` shape per ADR-001.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub bundle_version: u32,
    pub deployment: String,
    pub issued_at: String,
    pub deployment_root_pubkey: String,
    #[serde(default)]
    pub publishers: Vec<PublisherEntry>,
    #[serde(default)]
    pub extensions: Vec<ExtensionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherEntry {
    pub id: String,
    pub pubkey: String,
    /// Root signature over the publisher's pubkey concatenated with their id.
    pub pubkey_sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionEntry {
    pub name: String,
    pub version: String,
    pub wheel: String,
    pub sha256: String,
    pub publisher_id: String,
    pub sig_path: String,
}

/// A staged extension wheel on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedExtension {
    pub name: String,
    pub version: String,
    pub wheel_path: PathBuf,
    pub publisher_id: String,
}

/// Top-level result of `stage_bundle`: where the SDK landed plus a list of
/// staged extension wheels.
#[derive(Debug)]
#[allow(dead_code)] // Consumed by integration tests + future #586 CLI side.
pub struct StagedBundle {
    pub deployment: String,
    pub sdk_version: String,
    pub sdk_path: PathBuf,
    pub extensions: Vec<StagedExtension>,
}

/// Fetch, verify, decompress, and stage a deployment bundle on disk.
///
/// `host` is the canonical deployment host; `doc` is the capability
/// document already validated against the pinned key; `root_key` is the
/// pinned Ed25519 deployment-root key that signed both the doc and the
/// bundle. Returns the on-disk staged locations.
pub fn stage_bundle(
    host: &str,
    doc: &CapabilityDoc,
    root_key: &VerifyingKey,
) -> Result<StagedBundle, Error> {
    // 1. Download to a per-deployment cache slot.
    let cache_dir = dirs::huitzo_home().join("cache").join(host);
    fs::create_dir_all(&cache_dir).map_err(|e| {
        Error::Manifest(format!(
            "failed to create cache dir {}: {e}",
            cache_dir.display()
        ))
    })?;
    let bundle_path = cache_dir.join(format!("sdk-{}.tar.zst", doc.sdk.version));

    eprintln!("  Downloading {}...", doc.sdk.bundle_url);
    download::stream_to_file_with_hash(&doc.sdk.bundle_url, &bundle_path, &doc.sdk.bundle_sha256)?;
    eprintln!("  Checksum verified.");

    // 2. Verify the bundle signature against the raw bytes on disk.
    let bundle_bytes = fs::read(&bundle_path).map_err(|e| {
        Error::Manifest(format!(
            "failed to re-read bundle {}: {e}",
            bundle_path.display()
        ))
    })?;
    verify_signature(&bundle_bytes, &doc.sdk.bundle_signature, root_key, "bundle")?;
    eprintln!("  Signature verified.");

    // 3. Decompress + untar into a staging directory under the deployment.
    let sdk_target = dirs::sdk_dir().join(host).join(&doc.sdk.version);
    if sdk_target.exists() {
        fs::remove_dir_all(&sdk_target).map_err(|e| {
            Error::Manifest(format!(
                "failed to clear stale SDK dir {}: {e}",
                sdk_target.display()
            ))
        })?;
    }
    fs::create_dir_all(&sdk_target).map_err(|e| {
        Error::Manifest(format!(
            "failed to create SDK dir {}: {e}",
            sdk_target.display()
        ))
    })?;
    extract_tar_zst(&bundle_bytes, &sdk_target)?;

    // 4. Read + verify the bundle manifest against the root key.
    let manifest_path = sdk_target.join("bundle-manifest.json");
    let manifest_sig_path = sdk_target.join("signatures").join("bundle-manifest.sig");
    let manifest_bytes = fs::read(&manifest_path).map_err(|_| Error::BundleVerify {
        reason: format!("bundle is missing {}", manifest_path.display()),
    })?;
    let manifest_sig = fs::read(&manifest_sig_path).map_err(|_| Error::BundleVerify {
        reason: format!("bundle is missing {}", manifest_sig_path.display()),
    })?;
    verify_raw_signature(&manifest_bytes, &manifest_sig, root_key, "bundle-manifest")?;
    let manifest: BundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| Error::BundleVerify {
            reason: format!("bundle-manifest.json is not valid JSON: {e}"),
        })?;

    // 5. Verify each publisher pubkey is signed by the root, and build
    //    a lookup table of publisher → verifying key.
    let mut publisher_keys: std::collections::HashMap<String, VerifyingKey> =
        std::collections::HashMap::new();
    for pubentry in &manifest.publishers {
        let pubkey = crate::keys::decode_pubkey(&pubentry.pubkey)?;
        let signed_message = publisher_signed_message(&pubentry.id, pubkey.as_bytes());
        let sig_bytes = decode_signature(&pubentry.pubkey_sig, "publisher pubkey")?;
        root_key
            .verify(&signed_message, &Signature::from_bytes(&sig_bytes))
            .map_err(|e| Error::BundleVerify {
                reason: format!(
                    "publisher '{}' pubkey is not signed by the deployment root: {e}",
                    pubentry.id
                ),
            })?;
        publisher_keys.insert(pubentry.id.clone(), pubkey);
    }

    // 6. Verify + stage each declared extension.
    let mut staged = Vec::new();
    for ext in &manifest.extensions {
        let wheel_path_in_bundle = sdk_target.join(&ext.wheel);
        let sig_path_in_bundle = sdk_target.join(&ext.sig_path);

        let wheel_bytes = fs::read(&wheel_path_in_bundle).map_err(|_| Error::BundleVerify {
            reason: format!("bundle is missing wheel {}", wheel_path_in_bundle.display()),
        })?;
        let sig_bytes = fs::read(&sig_path_in_bundle).map_err(|_| Error::BundleVerify {
            reason: format!(
                "bundle is missing signature {}",
                sig_path_in_bundle.display()
            ),
        })?;

        // SHA-256 match against the manifest's declaration.
        let mut hasher = Sha256::new();
        hasher.update(&wheel_bytes);
        let computed: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !computed.eq_ignore_ascii_case(&ext.sha256) {
            return Err(Error::BundleVerify {
                reason: format!(
                    "wheel {} sha256 mismatch (expected {}, got {})",
                    ext.wheel, ext.sha256, computed
                ),
            });
        }

        let publisher_key =
            publisher_keys
                .get(&ext.publisher_id)
                .ok_or_else(|| Error::BundleVerify {
                    reason: format!(
                        "wheel {} declares publisher '{}' which is not in the bundle manifest",
                        ext.wheel, ext.publisher_id
                    ),
                })?;
        verify_raw_signature(&wheel_bytes, &sig_bytes, publisher_key, &ext.wheel)?;

        // Move the wheel into its canonical per-extension slot.
        let wheel_filename =
            Path::new(&ext.wheel)
                .file_name()
                .ok_or_else(|| Error::BundleVerify {
                    reason: format!("malformed wheel path: {}", ext.wheel),
                })?;
        let dest_dir = dirs::ext_dir()
            .join(host)
            .join(&ext.name)
            .join(&ext.version);
        fs::create_dir_all(&dest_dir).map_err(|e| {
            Error::Manifest(format!(
                "failed to create ext dir {}: {e}",
                dest_dir.display()
            ))
        })?;
        let dest = dest_dir.join(wheel_filename);
        fs::write(&dest, &wheel_bytes).map_err(|e| {
            Error::Manifest(format!(
                "failed to write staged wheel {}: {e}",
                dest.display()
            ))
        })?;

        staged.push(StagedExtension {
            name: ext.name.clone(),
            version: ext.version.clone(),
            wheel_path: dest,
            publisher_id: ext.publisher_id.clone(),
        });
        eprintln!("  Staged extension {} {}", ext.name, ext.version);
    }

    // 7. Write the per-deployment index so the CLI can enumerate staged
    //    wheels without re-fetching the bundle.
    write_ext_index(host, &staged)?;

    Ok(StagedBundle {
        deployment: host.to_string(),
        sdk_version: doc.sdk.version.clone(),
        sdk_path: sdk_target,
        extensions: staged,
    })
}

/// Canonical signed-message form for a publisher pubkey entry: the raw
/// id bytes concatenated with the raw 32-byte pubkey. Stable across
/// publisher tooling, backend, and launcher.
fn publisher_signed_message(id: &str, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len() + 32);
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(pubkey);
    out
}

fn write_ext_index(host: &str, staged: &[StagedExtension]) -> Result<(), Error> {
    #[derive(Serialize)]
    struct Index<'a> {
        deployment: &'a str,
        extensions: &'a [StagedExtension],
    }
    let index = Index {
        deployment: host,
        extensions: staged,
    };
    let index_path = dirs::ext_dir().join(host).join("index.json");
    if let Some(parent) = index_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Manifest(format!("failed to create ext index dir: {e}")))?;
    }
    let json = serde_json::to_vec_pretty(&index)
        .map_err(|e| Error::Manifest(format!("failed to serialize ext index: {e}")))?;
    fs::write(&index_path, &json)
        .map_err(|e| Error::Manifest(format!("failed to write {}: {e}", index_path.display())))?;
    Ok(())
}

fn extract_tar_zst(bundle_bytes: &[u8], dest: &Path) -> Result<(), Error> {
    let cursor = std::io::Cursor::new(bundle_bytes);
    let decoder = zstd::stream::read::Decoder::new(cursor).map_err(|e| Error::BundleVerify {
        reason: format!("zstd decode failed: {e}"),
    })?;
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    archive.set_overwrite(true);
    for entry in archive.entries().map_err(|e| Error::BundleVerify {
        reason: format!("tar read failed: {e}"),
    })? {
        let mut entry = entry.map_err(|e| Error::BundleVerify {
            reason: format!("tar entry read failed: {e}"),
        })?;
        let path = entry.path().map_err(|e| Error::BundleVerify {
            reason: format!("tar entry has invalid path: {e}"),
        })?;
        // Reject any entry that would escape `dest` (path traversal guard).
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        }) {
            return Err(Error::BundleVerify {
                reason: format!("tar entry escapes destination: {}", path.display()),
            });
        }
        entry.unpack_in(dest).map_err(|e| Error::BundleVerify {
            reason: format!("tar unpack failed: {e}"),
        })?;
    }
    Ok(())
}

fn decode_signature(b64: &str, label: &str) -> Result<[u8; 64], Error> {
    let raw = BASE64.decode(b64.trim()).map_err(|e| Error::BundleVerify {
        reason: format!("{label} signature is not valid base64: {e}"),
    })?;
    if raw.len() != 64 {
        return Err(Error::BundleVerify {
            reason: format!("{label} signature must be 64 bytes, got {}", raw.len()),
        });
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&raw);
    Ok(buf)
}

fn verify_signature(
    message: &[u8],
    sig_b64: &str,
    key: &VerifyingKey,
    label: &str,
) -> Result<(), Error> {
    let buf = decode_signature(sig_b64, label)?;
    key.verify(message, &Signature::from_bytes(&buf))
        .map_err(|e| Error::BundleVerify {
            reason: format!("{label} signature did not verify: {e}"),
        })
}

fn verify_raw_signature(
    message: &[u8],
    sig_bytes: &[u8],
    key: &VerifyingKey,
    label: &str,
) -> Result<(), Error> {
    if sig_bytes.len() != 64 {
        return Err(Error::BundleVerify {
            reason: format!(
                "{label} raw signature must be 64 bytes, got {}",
                sig_bytes.len()
            ),
        });
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(sig_bytes);
    key.verify(message, &Signature::from_bytes(&buf))
        .map_err(|e| Error::BundleVerify {
            reason: format!("{label} signature did not verify: {e}"),
        })
}

/// Compute the SHA-256 hex digest of `bytes`. Exposed for tests + callers
/// that want to compare against capability hashes directly.
#[allow(dead_code)]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Read a file off disk and return its SHA-256 hex digest.
#[allow(dead_code)]
pub fn sha256_file(path: &Path) -> Result<String, Error> {
    let mut file = fs::File::open(path)
        .map_err(|e| Error::Manifest(format!("failed to open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| Error::Manifest(format!("read failed: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn publisher_signed_message_is_id_then_key() {
        let mut k = [0u8; 32];
        k[0] = 0xaa;
        let msg = publisher_signed_message("huitzo", &k);
        assert_eq!(&msg[..6], b"huitzo");
        assert_eq!(&msg[6..], &k);
    }

    #[test]
    fn decode_signature_rejects_short_input() {
        let bad = BASE64.encode(b"nope");
        assert!(decode_signature(&bad, "test").is_err());
    }

    #[test]
    fn verify_signature_round_trip() {
        let signing = SigningKey::generate(&mut OsRng);
        let msg = b"hello world";
        let sig = signing.sign(msg);
        let b64 = BASE64.encode(sig.to_bytes());
        verify_signature(msg, &b64, &signing.verifying_key(), "test").unwrap();
    }

    #[test]
    fn verify_signature_rejects_tamper() {
        let signing = SigningKey::generate(&mut OsRng);
        let msg = b"hello world";
        let sig = signing.sign(msg);
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 0x01;
        let b64 = BASE64.encode(bytes);
        assert!(matches!(
            verify_signature(msg, &b64, &signing.verifying_key(), "test"),
            Err(Error::BundleVerify { .. })
        ));
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
