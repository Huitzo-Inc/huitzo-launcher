// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! Integration tests for the capability fetch + verify path.

mod common;

use common::{TempHome, make_signing_key, sample_capability, sign_capability};
use httpmock::MockServer;
use huitzo_launcher::capabilities;
use huitzo_launcher::errors::Error;

#[test]
fn fetch_returns_parsed_doc_on_happy_path() {
    let _home = TempHome::new();
    let root = make_signing_key();
    let mut doc = sample_capability(
        "test.example",
        "https://test.example/bundle.tar.zst",
        b"placeholder",
    );
    sign_capability(&mut doc, &root);

    let server = MockServer::start();
    let body = serde_json::to_string(&doc).unwrap();
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v1/capabilities");
        then.status(200)
            .header("content-type", "application/json")
            .body(&body);
    });

    let (fetched, raw) = capabilities::fetch(&server.url("")).unwrap();
    mock.assert();
    assert_eq!(fetched.deployment, "test.example");
    assert_eq!(fetched.sdk.version, "0.5.2");
    assert!(!raw.is_empty());
}

#[test]
fn fetch_and_verify_pins_on_first_use_then_validates() {
    let home = TempHome::new();
    let root = make_signing_key();
    let mut doc = sample_capability(
        "test.example",
        "https://test.example/bundle.tar.zst",
        b"placeholder",
    );
    sign_capability(&mut doc, &root);

    let server = MockServer::start();
    let body = serde_json::to_string(&doc).unwrap();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v1/capabilities");
        then.status(200).body(&body);
    });

    let (fetched, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    assert_eq!(fetched.deployment, "test.example");
    assert_eq!(pinned.key.as_bytes(), root.verifying_key().as_bytes());

    drop(home);
}

#[test]
fn fetch_and_verify_rejects_swapped_root_key() {
    let home = TempHome::new();
    let original_root = make_signing_key();
    let attacker_root = make_signing_key();
    let mut doc = sample_capability(
        "test.example",
        "https://test.example/bundle.tar.zst",
        b"placeholder",
    );
    sign_capability(&mut doc, &original_root);

    let server = MockServer::start();
    let body = serde_json::to_string(&doc).unwrap();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v1/capabilities");
        then.status(200).body(&body);
    });

    // Pin the legitimate root first.
    capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();

    // Now the deployment serves a doc signed by a different key + ships its
    // pubkey along with the doc. Trust must fail loudly.
    let mut malicious = doc.clone();
    sign_capability(&mut malicious, &attacker_root);
    let body = serde_json::to_string(&malicious).unwrap();
    let server2 = MockServer::start();
    server2.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v1/capabilities");
        then.status(200).body(&body);
    });

    let err = capabilities::fetch_and_verify(&server2.url(""), "test.example", false).unwrap_err();
    assert!(matches!(err, Error::TrustViolation { .. }));

    drop(home);
}

#[test]
fn verify_rejects_tampered_body() {
    let _home = TempHome::new();
    let root = make_signing_key();
    let mut doc = sample_capability(
        "test.example",
        "https://test.example/bundle.tar.zst",
        b"placeholder",
    );
    sign_capability(&mut doc, &root);

    // Tamper after signing: bundle_sha256 is part of the canonical message.
    doc.sdk.bundle_sha256 = "00".repeat(32);

    let err = capabilities::verify(&doc, &root.verifying_key()).unwrap_err();
    assert!(matches!(err, Error::BundleVerify { .. }));
}

#[test]
fn canonical_signed_message_is_concatenation() {
    let mut doc = sample_capability(
        "test.example",
        "https://test.example/bundle.tar.zst",
        b"placeholder",
    );
    doc.sdk.bundle_sha256 = "abc123".to_string();
    doc.sdk.version = "1.2.3".to_string();
    doc.issued_at = "2026-05-23T20:00:00Z".to_string();
    let msg = capabilities::canonical_signed_message(&doc);
    assert_eq!(msg, b"abc1231.2.32026-05-23T20:00:00Z");
}

// ---- #26: overlap-window rotation, end to end ---------------------------

use common::{attest_rotation, iso_days_from_now};
use ed25519_dalek::SigningKey;
use huitzo_launcher::keys;

/// Serve one capability document at `/api/v1/capabilities`.
fn serve(doc: &huitzo_launcher::capabilities::CapabilityDoc) -> httpmock::MockServer {
    let server = MockServer::start();
    let body = serde_json::to_string(doc).unwrap();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/api/v1/capabilities");
        then.status(200).body(&body);
    });
    server
}

fn doc_signed_by(root: &SigningKey) -> huitzo_launcher::capabilities::CapabilityDoc {
    let mut doc = sample_capability(
        "test.example",
        "https://test.example/bundle.tar.zst",
        b"placeholder",
    );
    sign_capability(&mut doc, root);
    doc
}

#[test]
fn rotation_offer_is_ignored_on_first_contact() {
    let home = TempHome::new();
    let root = make_signing_key();
    let next = make_signing_key();
    let mut doc = doc_signed_by(&root);
    attest_rotation(
        &mut doc,
        "test.example",
        &root,
        &root,
        &next,
        &iso_days_from_now(30),
    );
    let server = serve(&doc);

    let (_doc, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    assert!(
        pinned.metadata.rotation.is_none(),
        "TOFU first contact must pin public_key only"
    );
    assert!(
        keys::pin_or_load("test.example", &next.verifying_key(), false).is_err(),
        "the advertised next key must not have been accepted"
    );

    drop(home);
}

#[test]
fn attested_rotation_lets_login_succeed_under_both_keys() {
    let home = TempHome::new();
    let root = make_signing_key();
    let next = make_signing_key();

    // 1. Plain first contact — pins `root`.
    let plain = doc_signed_by(&root);
    let server = serve(&plain);
    capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();

    // 2. Deployment starts advertising the overlap.
    let mut with_offer = doc_signed_by(&root);
    with_offer.trust_advisory_url = Some("https://test.example/rotation".to_string());
    attest_rotation(
        &mut with_offer,
        "test.example",
        &root,
        &root,
        &next,
        &iso_days_from_now(30),
    );
    let server = serve(&with_offer);
    let (_doc, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    let rotation = pinned.metadata.rotation.expect("overlap opened");
    assert_eq!(
        rotation.next_public_key,
        keys::encode_key(&next.verifying_key())
    );
    assert!(rotation.notice_shown);

    // 3. Deployment cuts over: the document is now signed by `next`. Login
    //    succeeds quietly, and the old key is pruned.
    let cutover = doc_signed_by(&next);
    let server = serve(&cutover);
    let (_doc, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    assert_eq!(pinned.key.as_bytes(), next.verifying_key().as_bytes());
    assert!(pinned.metadata.rotation.is_none());

    // 4. A document signed by the retired key is now a trust violation.
    let stale = doc_signed_by(&root);
    let server = serve(&stale);
    let err = capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap_err();
    assert!(matches!(err, Error::TrustViolation { .. }));

    drop(home);
}

#[test]
fn hostile_next_key_from_a_mitm_is_refused() {
    let home = TempHome::new();
    let root = make_signing_key();
    let attacker = make_signing_key();

    let plain = doc_signed_by(&root);
    let server = serve(&plain);
    capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();

    // MITM: keeps the legitimate doc + signature (so `doc_signature` still
    // verifies) but bolts on their own next key, attested by themselves.
    let mut hostile = doc_signed_by(&root);
    attest_rotation(
        &mut hostile,
        "test.example",
        &root,
        &attacker,
        &attacker,
        &iso_days_from_now(30),
    );
    let server = serve(&hostile);
    let (_doc, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    assert!(pinned.metadata.rotation.is_none());

    // The attacker's key is not in the accepted set, so their own signed
    // document is refused.
    let attacker_doc = doc_signed_by(&attacker);
    let server = serve(&attacker_doc);
    let err = capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap_err();
    assert!(matches!(err, Error::TrustViolation { .. }));

    drop(home);
}

#[test]
fn rotation_fields_must_arrive_as_a_complete_trio() {
    let home = TempHome::new();
    let root = make_signing_key();
    let next = make_signing_key();

    let plain = doc_signed_by(&root);
    let server = serve(&plain);
    capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();

    // next_public_key present, attestation missing.
    let mut partial = doc_signed_by(&root);
    attest_rotation(
        &mut partial,
        "test.example",
        &root,
        &root,
        &next,
        &iso_days_from_now(30),
    );
    partial.next_key_attestation = None;
    let server = serve(&partial);
    let (_doc, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    assert!(pinned.metadata.rotation.is_none());

    // Attestation present but structurally malformed.
    let mut malformed = doc_signed_by(&root);
    attest_rotation(
        &mut malformed,
        "test.example",
        &root,
        &root,
        &next,
        &iso_days_from_now(30),
    );
    malformed.next_key_attestation = Some("not-base64!!".to_string());
    let server = serve(&malformed);
    let (_doc, pinned) =
        capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();
    assert!(pinned.metadata.rotation.is_none());

    // Empty strings mean "no rotation", not "malformed".
    let mut empties = doc_signed_by(&root);
    empties.next_public_key = Some(String::new());
    empties.next_key_not_after = Some("  ".to_string());
    empties.next_key_attestation = None;
    assert!(
        capabilities::parse_rotation_offer(&empties)
            .unwrap()
            .is_none()
    );

    drop(home);
}

#[test]
fn document_signed_by_the_next_key_before_any_offer_is_refused() {
    let home = TempHome::new();
    let root = make_signing_key();
    let next = make_signing_key();

    let plain = doc_signed_by(&root);
    let server = serve(&plain);
    capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap();

    // No overlap was ever opened, so a document signed by a second key is a
    // plain trust violation — the launcher must never verify under a key it
    // did not legitimately accept.
    let jumped = doc_signed_by(&next);
    let server = serve(&jumped);
    let err = capabilities::fetch_and_verify(&server.url(""), "test.example", false).unwrap_err();
    assert!(matches!(err, Error::TrustViolation { .. }));

    drop(home);
}
