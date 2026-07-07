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
