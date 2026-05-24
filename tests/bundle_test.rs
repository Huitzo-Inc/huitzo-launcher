//! Integration tests for the bundle fetch + verify + stage path.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{
    TempHome, build_bundle_tarball, make_extension_entry, make_publisher_entry, make_signing_key,
    sample_capability, sha256_hex, sign_capability,
};
use ed25519_dalek::Signer;
use httpmock::MockServer;
use huitzo_launcher::bundle::{self, BundleManifest};
use huitzo_launcher::capabilities::CapabilityDoc;
use huitzo_launcher::dirs;
use huitzo_launcher::errors::Error;

/// Build a fully-signed bundle + capability doc tied together.
///
/// Returns `(capability_doc, raw_bundle_bytes, mock_bundle_url)` ready to
/// hand to `bundle::stage_bundle`. The capability doc's
/// `bundle_signature` is over the raw bundle bytes (per ADR-001).
fn build_test_bundle(
    server: &MockServer,
    deployment: &str,
    root: &ed25519_dalek::SigningKey,
    with_extension: bool,
) -> (CapabilityDoc, Vec<u8>) {
    let publisher = make_signing_key();
    let publisher_entry = make_publisher_entry("huitzo", root, &publisher);

    let (extensions, wheels) = if with_extension {
        let wheel_bytes = b"PK\x03\x04 fake wheel bytes".to_vec();
        let wheel_sig = publisher.sign(&wheel_bytes).to_bytes().to_vec();
        let ext_entry = make_extension_entry(
            "hubspot",
            "1.4.0",
            "hubspot-1.4.0.whl",
            &wheel_bytes,
            "huitzo",
        );
        let wheels = vec![("hubspot-1.4.0.whl".to_string(), wheel_bytes, wheel_sig)];
        (vec![ext_entry], wheels)
    } else {
        (vec![], vec![])
    };

    let manifest = BundleManifest {
        bundle_version: 1,
        deployment: deployment.to_string(),
        issued_at: "2026-05-23T20:00:00Z".to_string(),
        deployment_root_pubkey: BASE64.encode(root.verifying_key().as_bytes()),
        publishers: vec![publisher_entry],
        extensions,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let manifest_sig = root.sign(&manifest_bytes).to_bytes().to_vec();

    let bundle_bytes = build_bundle_tarball(&manifest, &manifest_sig, &wheels);

    // Capability doc references the bundle by URL + SHA-256 + signature.
    let bundle_url = server.url("/bundle.tar.zst");
    let mut doc = sample_capability(deployment, &bundle_url, &bundle_bytes);
    let bundle_sig = root.sign(&bundle_bytes);
    doc.sdk.bundle_signature = BASE64.encode(bundle_sig.to_bytes());
    sign_capability(&mut doc, root);

    (doc, bundle_bytes)
}

#[test]
fn stage_bundle_happy_path_with_extension() {
    let home = TempHome::new();
    let server = MockServer::start();
    let root = make_signing_key();
    let (doc, bundle_bytes) = build_test_bundle(&server, "test.example", &root, true);

    let bundle_clone = bundle_bytes.clone();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/bundle.tar.zst");
        then.status(200).body(bundle_clone);
    });

    let staged = bundle::stage_bundle("test.example", &doc, &root.verifying_key()).unwrap();
    assert_eq!(staged.deployment, "test.example");
    assert_eq!(staged.sdk_version, "0.5.2");
    assert!(staged.sdk_path.exists());
    assert!(staged.sdk_path.join("bundle-manifest.json").exists());
    assert_eq!(staged.extensions.len(), 1);
    assert!(staged.extensions[0].wheel_path.exists());

    // Per-deployment index.json is written for the CLI side.
    let index = dirs::ext_dir().join("test.example").join("index.json");
    assert!(index.exists());

    drop(home);
}

#[test]
fn stage_bundle_rejects_tampered_tarball() {
    let home = TempHome::new();
    let server = MockServer::start();
    let root = make_signing_key();
    let (doc, bundle_bytes) = build_test_bundle(&server, "test.example", &root, false);

    // Tamper: append 64 random bytes. Checksum will fail.
    let mut tampered = bundle_bytes.clone();
    tampered.extend_from_slice(&[0xff; 64]);

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/bundle.tar.zst");
        then.status(200).body(tampered);
    });

    let err = bundle::stage_bundle("test.example", &doc, &root.verifying_key()).unwrap_err();
    assert!(matches!(err, Error::BundleVerify { .. }));

    drop(home);
}

#[test]
fn stage_bundle_rejects_tampered_signature() {
    let home = TempHome::new();
    let server = MockServer::start();
    let root = make_signing_key();
    let (mut doc, bundle_bytes) = build_test_bundle(&server, "test.example", &root, false);

    // Flip a bit in the bundle_signature; checksum still passes, sig must fail.
    let mut sig_bytes = BASE64.decode(&doc.sdk.bundle_signature).unwrap();
    sig_bytes[0] ^= 0x01;
    doc.sdk.bundle_signature = BASE64.encode(sig_bytes);

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/bundle.tar.zst");
        then.status(200).body(bundle_bytes);
    });

    let err = bundle::stage_bundle("test.example", &doc, &root.verifying_key()).unwrap_err();
    assert!(matches!(err, Error::BundleVerify { .. }));

    drop(home);
}

#[test]
fn stage_bundle_rejects_unsigned_publisher() {
    let home = TempHome::new();
    let server = MockServer::start();
    let root = make_signing_key();
    let rogue_root = make_signing_key();

    // Build the manifest, but countersign the publisher with a key the
    // launcher hasn't pinned — root-key signature check on publisher
    // pubkey must fail.
    let publisher = make_signing_key();
    let publisher_entry = make_publisher_entry("huitzo", &rogue_root, &publisher);

    let wheel_bytes = b"PK\x03\x04 fake".to_vec();
    let wheel_sig = publisher.sign(&wheel_bytes).to_bytes().to_vec();
    let ext_entry = make_extension_entry(
        "hubspot",
        "1.4.0",
        "hubspot-1.4.0.whl",
        &wheel_bytes,
        "huitzo",
    );

    let manifest = BundleManifest {
        bundle_version: 1,
        deployment: "test.example".to_string(),
        issued_at: "2026-05-23T20:00:00Z".to_string(),
        deployment_root_pubkey: BASE64.encode(root.verifying_key().as_bytes()),
        publishers: vec![publisher_entry],
        extensions: vec![ext_entry],
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let manifest_sig = root.sign(&manifest_bytes).to_bytes().to_vec();
    let bundle_bytes = build_bundle_tarball(
        &manifest,
        &manifest_sig,
        &[("hubspot-1.4.0.whl".to_string(), wheel_bytes, wheel_sig)],
    );

    let bundle_url = server.url("/bundle.tar.zst");
    let mut doc = sample_capability("test.example", &bundle_url, &bundle_bytes);
    doc.sdk.bundle_signature = BASE64.encode(root.sign(&bundle_bytes).to_bytes());
    sign_capability(&mut doc, &root);

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/bundle.tar.zst");
        then.status(200).body(bundle_bytes);
    });

    let err = bundle::stage_bundle("test.example", &doc, &root.verifying_key()).unwrap_err();
    match err {
        Error::BundleVerify { reason } => {
            assert!(
                reason.contains("publisher")
                    || reason.contains("deployment root")
                    || reason.contains("signed"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected BundleVerify, got {other:?}"),
    }

    drop(home);
}

#[test]
fn sha256_hex_helper_matches_known_vector() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
