// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

//! Integration tests for the TOFU pinning module.

mod common;

use common::{TempHome, make_signing_key};
use huitzo_launcher::dirs;
use huitzo_launcher::errors::Error;
use huitzo_launcher::keys;

#[test]
fn pin_or_load_creates_file_on_first_call() {
    let home = TempHome::new();
    let key = make_signing_key().verifying_key();

    let pinned = keys::pin_or_load("ai.example", &key, false).unwrap();
    assert_eq!(pinned.metadata.issuer, "ai.example");

    let key_path = dirs::pinned_key_path("ai.example");
    let meta_path = dirs::trust_meta_path("ai.example");
    assert!(
        key_path.exists(),
        "pubkey file missing at {}",
        key_path.display()
    );
    assert!(
        meta_path.exists(),
        "metadata file missing at {}",
        meta_path.display()
    );

    // Pubkey file is exactly 32 raw bytes.
    let raw = std::fs::read(&key_path).unwrap();
    assert_eq!(raw.len(), 32);
    assert_eq!(&raw[..], key.as_bytes());

    drop(home);
}

#[test]
fn pin_or_load_returns_same_key_on_second_call() {
    let home = TempHome::new();
    let key = make_signing_key().verifying_key();

    let first = keys::pin_or_load("ai.example", &key, false).unwrap();
    let second = keys::pin_or_load("ai.example", &key, false).unwrap();
    assert_eq!(first.metadata.fingerprint, second.metadata.fingerprint);
    assert_eq!(first.metadata.first_seen, second.metadata.first_seen);

    drop(home);
}

#[test]
fn pin_or_load_rejects_mutated_key() {
    let home = TempHome::new();
    let original = make_signing_key().verifying_key();
    let attacker = make_signing_key().verifying_key();

    keys::pin_or_load("ai.example", &original, false).unwrap();
    let err = keys::pin_or_load("ai.example", &attacker, false).unwrap_err();
    match err {
        Error::TrustViolation { stored, advertised } => {
            assert_ne!(stored, advertised);
            assert!(stored.starts_with("SHA256:"));
            assert!(advertised.starts_with("SHA256:"));
        }
        other => panic!("expected TrustViolation, got {other:?}"),
    }

    drop(home);
}

#[test]
fn force_rotate_overwrites_pinned_key() {
    let home = TempHome::new();
    let original = make_signing_key().verifying_key();
    let new_key = make_signing_key().verifying_key();

    keys::pin_or_load("ai.example", &original, false).unwrap();
    let rotated = keys::pin_or_load("ai.example", &new_key, true).unwrap();

    assert_eq!(rotated.key.as_bytes(), new_key.as_bytes());
    // Second load (no rotate) must now accept the new key.
    keys::pin_or_load("ai.example", &new_key, false).unwrap();

    drop(home);
}

#[test]
fn corrupted_pubkey_file_is_rejected() {
    let home = TempHome::new();
    let key = make_signing_key().verifying_key();
    keys::pin_or_load("ai.example", &key, false).unwrap();

    // Truncate the file on disk — load_pinned should fail loud.
    let path = dirs::pinned_key_path("ai.example");
    std::fs::write(&path, b"too-short").unwrap();
    let err = keys::load_pinned("ai.example").unwrap_err();
    assert!(matches!(err, Error::BundleVerify { .. }));

    drop(home);
}

#[test]
fn canonical_host_round_trips_and_includes_port() {
    assert_eq!(
        keys::canonical_host("https://huitzo.ai").unwrap(),
        "huitzo.ai"
    );
    assert_eq!(
        keys::canonical_host("https://staging.huitzo.ai:8443/foo").unwrap(),
        "staging.huitzo.ai:8443"
    );
}

// ---- #26: overlap-window rotation ---------------------------------------

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use huitzo_launcher::keys::{RotationOffer, canonical_rotation_message, encode_key};

/// Build a rotation offer as the deployment backend would, except that
/// `attestor` is parameterised so tests can forge one.
fn offer(
    host: &str,
    current: &VerifyingKey,
    attestor: &SigningKey,
    next: &VerifyingKey,
    not_after: &str,
) -> RotationOffer {
    let msg = canonical_rotation_message(host, &encode_key(current), &encode_key(next), not_after)
        .unwrap();
    RotationOffer {
        next_key: *next,
        not_after: not_after.to_string(),
        attestation: attestor.sign(&msg),
    }
}

#[test]
fn overlap_window_accepts_either_key_then_prunes_on_cutover() {
    let home = TempHome::new();
    let host = "ai.example";
    let current = make_signing_key();
    let next = make_signing_key();

    // First contact pins the current key only.
    let pinned = keys::pin_or_load(host, &current.verifying_key(), false).unwrap();
    assert!(pinned.first_use);
    keys::apply_rotation(host, pinned, None, None).unwrap();

    // Overlap opens on a later, attested fetch.
    let not_after = common::iso_days_from_now(30);
    let attested = offer(
        host,
        &current.verifying_key(),
        &current,
        &next.verifying_key(),
        &not_after,
    );
    let pinned = keys::pin_or_load(host, &current.verifying_key(), false).unwrap();
    keys::apply_rotation(
        host,
        pinned,
        Some(&attested),
        Some("https://example/rotation"),
    )
    .unwrap();

    // BOTH keys are now acceptable.
    keys::pin_or_load(host, &current.verifying_key(), false).unwrap();
    let via_next = keys::pin_or_load(host, &next.verifying_key(), false).unwrap();
    assert_eq!(via_next.key.as_bytes(), next.verifying_key().as_bytes());

    // Using the next key prunes the old one.
    keys::apply_rotation(host, via_next, None, None).unwrap();
    let err = keys::pin_or_load(host, &current.verifying_key(), false).unwrap_err();
    assert!(matches!(err, Error::TrustViolation { .. }));

    drop(home);
}

#[test]
fn pre_rotation_trust_file_on_disk_keeps_working() {
    let home = TempHome::new();
    let host = "ai.example";
    let key = make_signing_key().verifying_key();

    // Hand-write the exact pre-#26 on-disk state: raw 32-byte pubkey plus a
    // three-field sidecar with no `rotation` object.
    let trust_dir = dirs::trust_dir();
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::write(dirs::pinned_key_path(host), key.as_bytes()).unwrap();
    std::fs::write(
        dirs::trust_meta_path(host),
        format!(
            r#"{{"fingerprint":"{}","first_seen":"2026-02-02T02:02:02Z","issuer":"{host}"}}"#,
            keys::fingerprint(&key)
        ),
    )
    .unwrap();

    let loaded = keys::load_pinned(host).unwrap().unwrap();
    assert_eq!(loaded.metadata.first_seen, "2026-02-02T02:02:02Z");
    assert!(!loaded.first_use);

    // Identical behaviour to before: match passes, mismatch is a violation,
    // --launcher-trust-rotate still re-pins.
    keys::pin_or_load(host, &key, false).unwrap();
    let other = make_signing_key().verifying_key();
    assert!(matches!(
        keys::pin_or_load(host, &other, false).unwrap_err(),
        Error::TrustViolation { .. }
    ));
    keys::pin_or_load(host, &other, true).unwrap();

    drop(home);
}

#[test]
fn forged_attestation_never_widens_the_accepted_set() {
    let home = TempHome::new();
    let host = "ai.example";
    let current = make_signing_key();
    let attacker = make_signing_key();

    let pinned = keys::pin_or_load(host, &current.verifying_key(), false).unwrap();
    keys::apply_rotation(host, pinned, None, None).unwrap();

    // The attacker advertises their own key as `next_public_key` and signs
    // the attestation with it — the classic re-pinning attempt.
    let forged = offer(
        host,
        &current.verifying_key(),
        &attacker,
        &attacker.verifying_key(),
        &common::iso_days_from_now(30),
    );
    let pinned = keys::pin_or_load(host, &current.verifying_key(), false).unwrap();
    let out = keys::apply_rotation(host, pinned, Some(&forged), None).unwrap();
    assert!(out.metadata.rotation.is_none());

    let err = keys::pin_or_load(host, &attacker.verifying_key(), false).unwrap_err();
    assert!(matches!(err, Error::TrustViolation { .. }));

    drop(home);
}

#[test]
fn retired_key_cannot_be_reinstated_by_replaying_the_old_attestation() {
    let home = TempHome::new();
    let host = "ai.example";
    let old = make_signing_key();
    let new = make_signing_key();
    let not_after = common::iso_days_from_now(30);

    // old -> new, completed.
    let pinned = keys::pin_or_load(host, &old.verifying_key(), false).unwrap();
    keys::apply_rotation(host, pinned, None, None).unwrap();
    let forward = offer(
        host,
        &old.verifying_key(),
        &old,
        &new.verifying_key(),
        &not_after,
    );
    let pinned = keys::pin_or_load(host, &old.verifying_key(), false).unwrap();
    keys::apply_rotation(host, pinned, Some(&forward), None).unwrap();
    let pinned = keys::pin_or_load(host, &new.verifying_key(), false).unwrap();
    keys::apply_rotation(host, pinned, None, None).unwrap();

    // Replaying the captured old->new attestation now is inert: it is signed
    // by `old`, which is no longer pinned, and its canonical message names
    // `old` as the current key.
    let pinned = keys::pin_or_load(host, &new.verifying_key(), false).unwrap();
    let out = keys::apply_rotation(host, pinned, Some(&forward), None).unwrap();
    assert!(out.metadata.rotation.is_none());
    assert!(matches!(
        keys::pin_or_load(host, &old.verifying_key(), false).unwrap_err(),
        Error::TrustViolation { .. }
    ));

    drop(home);
}
