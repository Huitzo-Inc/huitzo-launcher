//! Deployment capability document — fetch + verify.
//!
//! The capability document is the launcher's wire contract with a
//! deployment. It advertises the active SDK bundle, the per-extension
//! wheels, and (critically) the deployment-root Ed25519 public key. The
//! launcher fetches `<api_url>/api/v1/capabilities`, TOFU-pins the
//! advertised public key on first contact, and verifies the document's
//! `doc_signature` against the pinned key on every subsequent fetch.
//!
//! Wire contract is owned by issue #584. We mirror the response shape
//! here; missing optional fields are tolerated so backend rollouts can
//! evolve without breaking already-deployed launchers.

use std::io::Read;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::errors::Error;
use crate::keys;

const CAPABILITIES_PATH: &str = "/api/v1/capabilities";
const FETCH_TIMEOUT_SECS: u64 = 5;

/// Top-level capability response from `/api/v1/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDoc {
    /// Deployment host string (e.g. `huitzo.ai`).
    pub deployment: String,
    /// SDK descriptor — bundle URL, version, hashes, signature.
    pub sdk: SdkInfo,
    /// Per-extension wheel descriptors.
    #[serde(default)]
    pub extensions: Vec<ExtensionInfo>,
    /// ISO-8601 UTC timestamp.
    pub issued_at: String,
    /// Deployment root public key, base64-encoded raw 32 bytes Ed25519.
    pub public_key: String,
    /// Ed25519 signature over the canonical "bundle_sha256 || version || issued_at" string.
    /// Base64-encoded raw 64 bytes.
    pub doc_signature: String,
    /// Optional advisory URL surfaced when the operator hits a key
    /// rotation. Free-form, populated by the deployment admin.
    #[serde(default)]
    pub trust_advisory_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkInfo {
    pub version: String,
    pub bundle_url: String,
    pub bundle_sha256: String,
    /// Ed25519 signature over the raw bundle bytes (base64).
    pub bundle_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub name: String,
    pub version: String,
    pub wheel_url: String,
    pub wheel_sha256: String,
    /// Ed25519 signature over the raw wheel bytes (base64).
    pub wheel_signature: String,
    /// Publisher id — used to look up the publisher pubkey in the bundle
    /// manifest when verifying per-wheel signatures (see ADR-001).
    pub publisher_id: String,
}

/// Fetch the capability document from `<api_url>/api/v1/capabilities`.
///
/// Returns the parsed document plus the raw response bytes (so signature
/// verification operates on the exact bytes received, not on a re-serialized
/// struct that may differ in whitespace / key order).
pub fn fetch(api_url: &str) -> Result<(CapabilityDoc, Vec<u8>), Error> {
    let url = format!("{}{}", api_url.trim_end_matches('/'), CAPABILITIES_PATH);

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(FETCH_TIMEOUT_SECS)))
        .build()
        .into();

    let mut response = agent
        .get(&url)
        .header(
            "User-Agent",
            &format!("huitzo-launcher/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "application/json")
        .call()
        .map_err(|e| Error::Network(format!("Failed to fetch {url}: {e}")))?;

    let mut buf = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut buf)
        .map_err(|e| Error::Network(format!("Failed to read capability response: {e}")))?;

    let doc: CapabilityDoc = serde_json::from_slice(&buf)
        .map_err(|e| Error::Network(format!("Failed to parse capability JSON: {e}")))?;

    Ok((doc, buf))
}

/// Compute the canonical signed-message bytes for a capability document.
///
/// Per #584: `sdk.bundle_sha256 || sdk.version || issued_at`. The
/// concatenation is the raw UTF-8 bytes of each field in order, no
/// separators, no length framing. Stable across launcher and backend.
pub fn canonical_signed_message(doc: &CapabilityDoc) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        doc.sdk.bundle_sha256.len() + doc.sdk.version.len() + doc.issued_at.len(),
    );
    out.extend_from_slice(doc.sdk.bundle_sha256.as_bytes());
    out.extend_from_slice(doc.sdk.version.as_bytes());
    out.extend_from_slice(doc.issued_at.as_bytes());
    out
}

/// Verify `doc.doc_signature` against `key` using the canonical
/// signed-message form. Returns `Ok(())` on success, `BundleVerify` on
/// any signature failure.
pub fn verify(doc: &CapabilityDoc, key: &VerifyingKey) -> Result<(), Error> {
    let sig_bytes = BASE64
        .decode(doc.doc_signature.trim())
        .map_err(|e| Error::BundleVerify {
            reason: format!("doc_signature is not valid base64: {e}"),
        })?;
    if sig_bytes.len() != 64 {
        return Err(Error::BundleVerify {
            reason: format!("doc_signature must be 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&buf);
    let msg = canonical_signed_message(doc);
    key.verify(&msg, &sig).map_err(|e| Error::BundleVerify {
        reason: format!("capability doc signature is invalid: {e}"),
    })
}

/// Fetch + TOFU-pin + verify in one step.
///
/// `host` is the canonical deployment host (see `keys::canonical_host`).
/// `force_rotate` is passed through to `keys::pin_or_load` and should
/// only be true when the operator has confirmed an emergency rotation
/// via `--launcher-trust-rotate`.
pub fn fetch_and_verify(
    api_url: &str,
    host: &str,
    force_rotate: bool,
) -> Result<(CapabilityDoc, keys::PinnedKey), Error> {
    let (doc, _raw) = fetch(api_url)?;
    let advertised = keys::decode_pubkey(&doc.public_key)?;
    let pinned = keys::pin_or_load(host, &advertised, force_rotate)?;
    verify(&doc, &pinned.key)?;
    Ok((doc, pinned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sign_doc(signing: &SigningKey, doc: &mut CapabilityDoc) {
        let sig = signing.sign(&canonical_signed_message(doc));
        doc.doc_signature = BASE64.encode(sig.to_bytes());
        doc.public_key = BASE64.encode(signing.verifying_key().as_bytes());
    }

    fn sample_doc() -> CapabilityDoc {
        CapabilityDoc {
            deployment: "test.example".to_string(),
            sdk: SdkInfo {
                version: "0.5.2".to_string(),
                bundle_url: "https://test.example/bundle.tar.zst".to_string(),
                bundle_sha256: "deadbeef".to_string(),
                bundle_signature: String::new(),
            },
            extensions: vec![],
            issued_at: "2026-05-23T20:00:00Z".to_string(),
            public_key: String::new(),
            doc_signature: String::new(),
            trust_advisory_url: None,
        }
    }

    #[test]
    fn canonical_message_is_field_concat() {
        let doc = sample_doc();
        let msg = canonical_signed_message(&doc);
        assert_eq!(msg, b"deadbeef0.5.22026-05-23T20:00:00Z");
    }

    #[test]
    fn verify_accepts_correct_signature() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut doc = sample_doc();
        sign_doc(&signing, &mut doc);
        verify(&doc, &signing.verifying_key()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut doc = sample_doc();
        sign_doc(&signing, &mut doc);
        // Flip one bit in the signature.
        let mut sig_bytes = BASE64.decode(&doc.doc_signature).unwrap();
        sig_bytes[0] ^= 0x01;
        doc.doc_signature = BASE64.encode(sig_bytes);
        let err = verify(&doc, &signing.verifying_key()).unwrap_err();
        assert!(matches!(err, Error::BundleVerify { .. }));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut doc = sample_doc();
        sign_doc(&signing, &mut doc);
        doc.sdk.version = "9.9.9".to_string();
        let err = verify(&doc, &signing.verifying_key()).unwrap_err();
        assert!(matches!(err, Error::BundleVerify { .. }));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let mut doc = sample_doc();
        sign_doc(&signing, &mut doc);
        let err = verify(&doc, &attacker.verifying_key()).unwrap_err();
        assert!(matches!(err, Error::BundleVerify { .. }));
    }

    #[test]
    fn verify_rejects_malformed_signature_length() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut doc = sample_doc();
        sign_doc(&signing, &mut doc);
        doc.doc_signature = BASE64.encode(b"too-short");
        let err = verify(&doc, &signing.verifying_key()).unwrap_err();
        match err {
            Error::BundleVerify { reason } => assert!(reason.contains("64 bytes")),
            _ => panic!("expected BundleVerify"),
        }
    }
}
