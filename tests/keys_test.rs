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
