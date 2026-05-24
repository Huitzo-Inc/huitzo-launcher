//! Shared test helpers for launcher integration tests.

use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use huitzo_launcher::bundle::{BundleManifest, ExtensionEntry, PublisherEntry};
use huitzo_launcher::capabilities::{CapabilityDoc, SdkInfo, canonical_signed_message};

/// HUITZO_HOME / env mutations are process-global; serialize them so
/// parallel tests don't stomp on each other's tempdirs.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

#[allow(dead_code)] // used across multiple test files; rustc lints per-binary
pub struct TempHome {
    pub dir: TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl TempHome {
    pub fn new() -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HUITZO_HOME", dir.path()) };
        Self { dir, _guard: guard }
    }

    #[allow(dead_code)]
    pub fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}

#[allow(dead_code)]
pub fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

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

#[allow(dead_code)]
pub fn sign_capability(doc: &mut CapabilityDoc, root: &SigningKey) {
    let msg = canonical_signed_message(doc);
    let sig = root.sign(&msg);
    doc.doc_signature = BASE64.encode(sig.to_bytes());
    doc.public_key = BASE64.encode(root.verifying_key().as_bytes());
}

#[allow(dead_code)]
pub fn sample_capability(deployment: &str, bundle_url: &str, bundle_bytes: &[u8]) -> CapabilityDoc {
    let bundle_sha = sha256_hex(bundle_bytes);
    CapabilityDoc {
        deployment: deployment.to_string(),
        sdk: SdkInfo {
            version: "0.5.2".to_string(),
            bundle_url: bundle_url.to_string(),
            bundle_sha256: bundle_sha,
            bundle_signature: String::new(),
        },
        extensions: vec![],
        issued_at: "2026-05-23T20:00:00Z".to_string(),
        public_key: String::new(),
        doc_signature: String::new(),
        trust_advisory_url: None,
    }
}

/// Build a minimal in-memory `.tar.zst` bundle containing the supplied
/// manifest + signatures + (optionally) extension wheels.
#[allow(dead_code)]
pub fn build_bundle_tarball(
    manifest: &BundleManifest,
    manifest_sig: &[u8],
    wheels: &[(String, Vec<u8>, Vec<u8>)], // (relative-path-in-tar, wheel bytes, sig bytes)
) -> Vec<u8> {
    let mut tar_buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);

        let manifest_json = serde_json::to_vec_pretty(manifest).unwrap();
        append_file(&mut builder, "bundle-manifest.json", &manifest_json);
        append_file(&mut builder, "signatures/bundle-manifest.sig", manifest_sig);
        for (rel_path, wheel_bytes, sig_bytes) in wheels {
            append_file(&mut builder, &format!("extensions/{rel_path}"), wheel_bytes);
            append_file(
                &mut builder,
                &format!("signatures/extensions/{rel_path}.sig"),
                sig_bytes,
            );
        }
        builder.finish().unwrap();
    }

    // Zstd-compress (default level).
    zstd::stream::encode_all(&tar_buf[..], 0).unwrap()
}

fn append_file<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, path, data).unwrap();
}

#[allow(dead_code)]
pub fn make_publisher_entry(id: &str, root: &SigningKey, publisher: &SigningKey) -> PublisherEntry {
    let verifying = publisher.verifying_key();
    let pubkey_bytes = verifying.as_bytes();
    let mut msg = Vec::with_capacity(id.len() + 32);
    msg.extend_from_slice(id.as_bytes());
    msg.extend_from_slice(pubkey_bytes);
    let sig = root.sign(&msg);
    PublisherEntry {
        id: id.to_string(),
        pubkey: BASE64.encode(pubkey_bytes),
        pubkey_sig: BASE64.encode(sig.to_bytes()),
    }
}

#[allow(dead_code)]
pub fn make_extension_entry(
    name: &str,
    version: &str,
    wheel_filename: &str,
    wheel_bytes: &[u8],
    publisher_id: &str,
) -> ExtensionEntry {
    ExtensionEntry {
        name: name.to_string(),
        version: version.to_string(),
        wheel: format!("extensions/{wheel_filename}"),
        sha256: sha256_hex(wheel_bytes),
        publisher_id: publisher_id.to_string(),
        sig_path: format!("signatures/extensions/{wheel_filename}.sig"),
    }
}
