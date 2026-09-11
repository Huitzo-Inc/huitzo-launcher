// Copyright (c) 2026 Huitzo Inc. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Huitzo-Source-Available

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
//! ## Routine overlap-window rotation (#26)
//!
//! A deployment that rotates its root key out of band would otherwise hard-
//! fail every developer with a `TrustViolation` until each of them ran
//! `--launcher-trust-rotate` by hand. To make routine rotation quiet, the
//! capability document may advertise the key it is rotating *to*, together
//! with an attestation produced by the key the launcher has **already
//! pinned**. During the resulting overlap window both keys are accepted.
//!
//! ### Wire contract
//!
//! Three optional fields on the capability document, supplied together or
//! not at all (see `capabilities::CapabilityDoc`):
//!
//! | Field | Type | Meaning |
//! |---|---|---|
//! | `next_public_key` | base64 of raw 32-byte Ed25519 public key | the key being rotated to |
//! | `next_key_not_after` | `YYYY-MM-DDTHH:MM:SSZ` | end of the overlap window, UTC, no offsets or fractional seconds |
//! | `next_key_attestation` | base64 of raw 64-byte Ed25519 signature | signature by the **current** root key over the canonical rotation message |
//!
//! The launcher records which key attested a live overlap and re-checks it
//! on every load, so an attestation is only ever honoured under the key
//! that produced it.
//!
//! These fields are deliberately *not* covered by `doc_signature`; the
//! attestation is their integrity protection. Stripping them degrades to
//! today's behaviour (fail closed at cutover), and substituting them fails
//! the attestation check.
//!
//! ### Canonical rotation message
//!
//! Unlike `capabilities::canonical_signed_message`, which concatenates raw
//! UTF-8 field bytes with no separators, the rotation message is **framed
//! and domain-separated**:
//!
//! ```text
//! "huitzo-key-rotation:v1" LF
//! <canonical host>         LF
//! <current_public_key b64> LF
//! <next_public_key b64>    LF
//! <next_key_not_after>     LF
//! ```
//!
//! The unframed style is safe for the capability document only because its
//! trailing fields happen to be constrained; it is *not* safe here. One of
//! the fields (the host) is variable-length and adjacent to another, so a
//! separator-free concatenation would let two different (host, key) pairs
//! produce identical signed bytes. Framing removes the ambiguity, and the
//! framing is injective because every component is rejected if it is empty
//! or contains `LF`/`CR`. The `huitzo-key-rotation:v1` prefix domain-
//! separates the attestation from `doc_signature`, so neither signature can
//! ever be reinterpreted as the other.
//!
//! Both base64 values are re-encoded by the launcher from the decoded raw
//! 32 bytes using the standard alphabet with padding, so non-canonical
//! base64 on the wire cannot change the signed bytes. The host is the
//! canonical host computed by `canonical_host` from the locally configured
//! deployment URL — never a value taken from the document — which binds the
//! attestation to exactly the trust file it mutates. A deployment served
//! under several hostnames must emit one attestation per canonical host.
//!
//! ### Rules
//!
//! * **Never on first use.** A TOFU first contact pins `public_key` only.
//!   There is nothing to attest against, so any advertised overlap is
//!   ignored.
//! * **Bounded.** `next_key_not_after` must be in the future and no more
//!   than `MAX_OVERLAP_SECS` (90 days) away, or the offer is ignored.
//! * **Next key must differ.** A `next_public_key` byte-identical to the
//!   currently pinned key is refused — there is nothing to rotate to, and
//!   accepting it would record a vacuous window.
//! * **No chaining.** While an overlap to key B is active, an offer naming
//!   a different key C is ignored; re-advertising B may only move the
//!   deadline.
//! * **Prune on use.** The first document that verifies under the next key
//!   promotes it to the pinned key and drops the old one.
//! * **Prune on expiry.** If the deadline passes without the next key ever
//!   being used, the overlap is discarded and trust reverts to the single
//!   pinned key. A later cutover then produces the ordinary
//!   `TrustViolation` and requires `--launcher-trust-rotate`. The window
//!   also closes on anything that makes its bounds unreadable or
//!   untrustworthy: an unparseable deadline or acceptance time, a clock
//!   below the sanity floor, a clock that has regressed behind the
//!   acceptance, or an acceptance older than `MAX_OVERLAP_SECS`. Closing
//!   early costs one `--launcher-trust-rotate`; closing late would mean an
//!   indefinitely widened accepted set.
//!
//! ### On-disk shape
//!
//! `<host>.pubkey` keeps its meaning exactly: the raw 32 bytes of the
//! single currently-pinned key, and it remains the authority on what is
//! pinned. The overlap lives in an optional `rotation` object inside the
//! `<host>.json` sidecar, so a single-key trust file written by an older
//! launcher deserializes and behaves unchanged.
//!
//! Trust files are read, decided on, and written without an inter-process
//! lock, so two launcher invocations racing on one host — or one
//! invocation killed between the two writes of a promotion — can leave the
//! sidecar describing a state the pubkey file has already moved past. Each
//! file is written atomically under its own staging name, so a race can
//! only lose a whole write, never interleave one. `load_pinned` then
//! reconciles the two in favour of the pubkey file: the fingerprint is
//! recomputed from it, and a `rotation` record is discarded outright if it
//! names the key that is already pinned or was attested by anything other
//! than the key that is pinned now. A lost update therefore cannot widen
//! the accepted set, reinstate a retired key, or repeat the one-time
//! notice — the next run simply re-derives the correct state.
//! `dirs::capability_lock_path` is reserved for tightening this further if
//! it ever matters. A process killed mid-write may also leave a
//! `<file>.<pid>.tmp` staging file behind; nothing ever reads those, so
//! they are inert clutter.
//!
//! ### What this does *not* defend against
//!
//! If the deployment's current root **private** key is compromised, this
//! feature buys the attacker nothing new *at that moment*: they could
//! already sign an arbitrary capability document and have any bundle
//! installed and executed. Being able to also mint a rotation attestation
//! is a second route to an outcome they already had. The attestation
//! defends against everyone who does *not* hold that private key — which
//! is the entire MITM / hostile-endpoint class.
//!
//! It does extend such a compromise along the *time* axis. An attacker who
//! uses the stolen key to complete a cutover to a key of their own leaves
//! that key pinned on every machine that saw the cutover, and it outlives
//! revocation of the stolen key: the operator's own recovery rotation
//! would have to be attested by whatever is pinned there, which is now the
//! attacker's key. Recovery from a root-key compromise is therefore
//! `--launcher-trust-rotate` on every affected machine, not a rotation.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dirs;
use crate::errors::Error;

/// Domain-separation prefix for the rotation attestation. Bumping this
/// invalidates every previously minted attestation, by design. The literal
/// is reproduced in the module doc for backend implementers.
const ROTATION_CONTEXT: &str = "huitzo-key-rotation:v1";

/// Hard upper bound on an overlap window. An unbounded two-key state is a
/// permanently widened attack surface, so a deployment cannot advertise a
/// deadline further out than this no matter what it signs.
const MAX_OVERLAP_SECS: u64 = 90 * 86_400;

/// Unix seconds for 2025-01-01T00:00:00Z. A clock reading earlier than this
/// predates every release of the launcher, so it is a broken clock rather
/// than a real instant — and a broken clock must not be able to keep a
/// two-key window open.
const CLOCK_SANITY_FLOOR: u64 = 1_735_689_600;

/// An in-flight overlap-window rotation, persisted in the trust sidecar.
///
/// Absent (`None`) on every single-key trust file, including every file
/// written by a launcher that predates #26.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationState {
    /// Human-facing fingerprint of the next key, for operator messaging.
    pub next_fingerprint: String,
    /// Base64 (standard alphabet, padded) of the next key's raw 32 bytes.
    pub next_public_key: String,
    /// ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ` end of the overlap window.
    pub not_after: String,
    /// When this launcher accepted the offer.
    pub accepted_at: String,
    /// Base64 of the key that attested this rotation — the key that was
    /// pinned at acceptance time. Re-checked against the pinned key on
    /// every load, so a record whose attester has since been superseded is
    /// discarded rather than honoured.
    #[serde(default)]
    pub attested_by: String,
    /// Whether the one-time operator notice has already been printed.
    #[serde(default)]
    pub notice_shown: bool,
}

/// Sidecar metadata persisted alongside the pinned raw-pubkey file.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustMetadata {
    /// `SHA256:` + colon-grouped hex fingerprint, matching the RFC UX.
    pub fingerprint: String,
    /// ISO-8601 UTC timestamp of first-seen.
    pub first_seen: String,
    /// Deployment / issuer host as advertised in the capability response.
    pub issuer: String,
    /// In-flight overlap-window rotation, if any. Defaulted so single-key
    /// sidecars written before #26 keep deserializing untouched.
    #[serde(default)]
    pub rotation: Option<RotationState>,
}

/// A rotation offer decoded from a capability document.
///
/// Construction only decodes; nothing here has been trusted yet. The
/// attestation is checked against the already-pinned key in
/// [`apply_rotation`].
#[derive(Debug, Clone)]
pub struct RotationOffer {
    /// The key the deployment intends to rotate to.
    pub next_key: VerifyingKey,
    /// Verbatim `next_key_not_after` from the document.
    pub not_after: String,
    /// `next_key_attestation`, decoded.
    pub attestation: Signature,
}

/// A pinned key + its metadata, ready for verification.
#[derive(Debug)]
pub struct PinnedKey {
    #[allow(dead_code)] // Surfaced via tests + diagnostic output.
    pub host: String,
    pub key: VerifyingKey,
    pub metadata: TrustMetadata,
    /// True when this resolution created the pin — TOFU first contact, or
    /// an operator-forced `--launcher-trust-rotate`. A rotation offer is
    /// ignored in that state: there was no prior key to attest against, so
    /// an advertised overlap carries no evidence at all.
    pub first_use: bool,
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
    let mut metadata: TrustMetadata = if meta_path.exists() {
        let s = fs::read_to_string(&meta_path)
            .map_err(|e| Error::Manifest(format!("failed to read trust metadata: {e}")))?;
        serde_json::from_str(&s).map_err(|e| {
            Error::Manifest(format!(
                "trust metadata at {} is corrupt: {e}",
                meta_path.display()
            ))
        })?
    } else {
        // Metadata sidecar was deleted; reconstruct what we can from the
        // key. Any overlap state is lost with it — fail closed, the
        // deployment will re-advertise the offer on the next fetch.
        TrustMetadata {
            fingerprint: fingerprint(&key),
            first_seen: now_iso8601(),
            issuer: host.to_string(),
            rotation: None,
        }
    };
    // The pubkey file is the authority on which key is pinned; the sidecar
    // only annotates it. If the two ever disagree — a sidecar hand-edited,
    // or a write interrupted between the two files — the operator-facing
    // fingerprint must still describe the key that will actually be used.
    metadata.fingerprint = fingerprint(&key);
    normalize_rotation(&mut metadata, &key);

    Ok(Some(PinnedKey {
        host: host.to_string(),
        key,
        metadata,
        first_use: false,
    }))
}

/// Pin `key` for `host`, writing the raw pubkey + metadata sidecar atomically.
///
/// Existing trust files for the host are overwritten. The caller is
/// responsible for deciding whether the overwrite is legitimate (first-use
/// TOFU, or operator-confirmed rotation via `--launcher-trust-rotate`).
pub fn pin(host: &str, key: &VerifyingKey) -> Result<PinnedKey, Error> {
    write_pinned_key(host, key)?;

    let metadata = TrustMetadata {
        fingerprint: fingerprint(key),
        first_seen: now_iso8601(),
        issuer: host.to_string(),
        rotation: None,
    };
    write_metadata(host, &metadata)?;

    Ok(PinnedKey {
        host: host.to_string(),
        key: *key,
        metadata,
        first_use: true,
    })
}

/// Drop a `rotation` record that the pinned key no longer supports.
///
/// Two cases, both reachable from an interrupted or raced write, and both
/// resolved in favour of the pubkey file:
///
/// * the record names the key that is *already* pinned — the rotation it
///   describes has completed, so it is vacuous;
/// * the record was attested by some other key — the deployment has moved
///   on since, and an attestation is only ever honoured under the key that
///   produced it.
///
/// Normalizing here rather than at the point of use means every reader
/// sees the same trust state, and a stale record can never widen the
/// accepted set even for one call.
fn normalize_rotation(metadata: &mut TrustMetadata, key: &VerifyingKey) {
    let pinned = encode_key(key);
    let stale = metadata
        .rotation
        .as_ref()
        .is_some_and(|r| r.next_public_key == pinned || r.attested_by != pinned);
    if stale {
        metadata.rotation = None;
    }
}

/// Persist the raw 32-byte pinned key for `host`, atomically and mode-0600.
fn write_pinned_key(host: &str, key: &VerifyingKey) -> Result<(), Error> {
    ensure_trust_dir()?;
    let key_path = dirs::pinned_key_path(host);
    write_atomic(&key_path, key.as_bytes())?;
    restrict_permissions(&key_path)
}

/// Persist the trust sidecar for `host`, atomically and mode-0600.
fn write_metadata(host: &str, metadata: &TrustMetadata) -> Result<(), Error> {
    ensure_trust_dir()?;
    let meta_path = dirs::trust_meta_path(host);
    let meta_json = serde_json::to_vec_pretty(metadata)
        .map_err(|e| Error::Manifest(format!("failed to serialize trust metadata: {e}")))?;
    write_atomic(&meta_path, &meta_json)?;
    restrict_permissions(&meta_path)
}

fn ensure_trust_dir() -> Result<(), Error> {
    let trust_dir = dirs::trust_dir();
    fs::create_dir_all(&trust_dir).map_err(|e| {
        Error::Manifest(format!(
            "failed to create trust dir {}: {e}",
            trust_dir.display()
        ))
    })
}

/// Phase 1 of trust resolution: choose the key a capability document is
/// allowed to be verified under.
///
/// * No key stored for `host` → TOFU first-use pin of `advertised`. A
///   rotation offer on first contact has nothing to attest against and is
///   ignored (see [`apply_rotation`], which is a no-op in this state).
/// * `advertised` equals the pinned key → return it.
/// * `advertised` equals the attested next key of an unexpired overlap →
///   return that, so the document is verified under the key the deployment
///   says signed it. Only keys already recorded in the trust file are ever
///   eligible; nothing from the document itself is trusted here.
/// * Otherwise → `TrustViolation`, unless `force_rotate` (the operator
///   explicitly opted in via `--launcher-trust-rotate`).
///
/// An overlap whose deadline has passed is discarded before the accepted
/// set is computed, so an expired window can never admit a key. That
/// discard is the one case where this function writes to disk before the
/// current document has been verified — safe, because expiry is decided
/// purely by the clock and the stored deadline, never by the document.
pub fn pin_or_load(
    host: &str,
    advertised: &VerifyingKey,
    force_rotate: bool,
) -> Result<PinnedKey, Error> {
    let Some(mut existing) = load_pinned(host)? else {
        eprintln!("Pinning new signing key for {host}");
        let pinned = pin(host, advertised)?;
        eprintln!("  fingerprint: {}", pinned.metadata.fingerprint);
        return Ok(pinned);
    };

    // Expire a stale overlap before anything can be selected from it.
    if let Some(rotation) = &existing.metadata.rotation
        && overlap_expired(rotation)
    {
        eprintln!(
            "Signing-key rotation window for {host} closed at {} without the new key being used.",
            rotation.not_after
        );
        eprintln!(
            "  Continuing to trust {} only.",
            existing.metadata.fingerprint
        );
        existing.metadata.rotation = None;
        // Advisory, exactly like offer intake: the window is closed in
        // memory either way, and failing to record that must not sink an
        // otherwise-serviceable capability refresh.
        if let Err(e) = write_metadata(host, &existing.metadata) {
            eprintln!("Warning: could not record the closed rotation window for {host}: {e}");
        }
    }

    if existing.key.as_bytes() == advertised.as_bytes() {
        return Ok(existing);
    }

    // Overlap window: the attested next key is equally acceptable.
    if let Some(rotation) = &existing.metadata.rotation
        && rotation.next_public_key == encode_key(advertised)
    {
        return Ok(PinnedKey {
            host: host.to_string(),
            key: *advertised,
            metadata: existing.metadata,
            first_use: false,
        });
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

/// Phase 3 of trust resolution: apply rotation state transitions now that
/// the capability document has been verified under `pinned.key`.
///
/// Must be called only after signature verification succeeds — a rotation
/// offer is only ever acted on from an authenticated document.
///
/// Two transitions happen here:
///
/// 1. **Promotion / prune-on-use.** If the document verified under the
///    attested next key, the deployment has cut over: the next key becomes
///    the pinned key and the old one is dropped.
/// 2. **Offer intake.** An attested `next_public_key` is recorded as an
///    overlap window, and the operator is told once.
///
/// A malformed, unattested or out-of-bounds offer is a warning, not an
/// error: ignoring it degrades to today's fail-closed behaviour.
pub fn apply_rotation(
    host: &str,
    pinned: PinnedKey,
    offer: Option<&RotationOffer>,
    advisory_url: Option<&str>,
) -> Result<PinnedKey, Error> {
    let PinnedKey {
        host: _,
        key,
        mut metadata,
        first_use,
    } = pinned;

    // 1. Promotion. The document verified under the next key, which only
    //    the holder of that key's private half could have produced.
    let cut_over = metadata
        .rotation
        .as_ref()
        .is_some_and(|r| r.next_public_key == encode_key(&key));
    if cut_over {
        let new_fingerprint = fingerprint(&key);
        eprintln!("Deployment {host} has completed its signing-key rotation.");
        eprintln!("  previously pinned: {}", metadata.fingerprint);
        eprintln!("  now pinned:        {new_fingerprint}");
        // first_seen describes the trust relationship with the deployment,
        // not the key, so it survives the rotation.
        metadata = TrustMetadata {
            fingerprint: new_fingerprint,
            first_seen: metadata.first_seen,
            issuer: host.to_string(),
            rotation: None,
        };
        write_pinned_key(host, &key)?;
        write_metadata(host, &metadata)?;
    }

    // 2. Offer intake. Skipped on a fresh pin: with nothing previously on
    //    disk, the "attestation" would only be the advertised key vouching
    //    for itself, which is no evidence at all.
    if let Some(offer) = offer.filter(|_| !first_use) {
        match consider_offer(host, &key, &metadata, offer) {
            Ok(Some(rotation)) => {
                if !rotation.notice_shown {
                    print_rotation_notice(host, &metadata.fingerprint, &rotation, advisory_url);
                }
                metadata.rotation = Some(RotationState {
                    notice_shown: true,
                    ..rotation
                });
                // Advisory: failing to record the window costs us nothing
                // but a repeated notice next launch, so it must not sink an
                // otherwise-verified capability refresh.
                if let Err(e) = write_metadata(host, &metadata) {
                    eprintln!("Warning: could not record the key rotation for {host}: {e}");
                    metadata.rotation = None;
                }
            }
            Ok(None) => {}
            Err(reason) => {
                eprintln!("Warning: ignoring advertised key rotation for {host}: {reason}");
            }
        }
    }

    Ok(PinnedKey {
        host: host.to_string(),
        key,
        metadata,
        first_use,
    })
}

/// Decide what an advertised rotation offer should do to the trust state.
///
/// `Ok(None)` means "valid but nothing changes". `Err` carries an operator-
/// facing reason the offer was refused; refusal is always safe because it
/// leaves the launcher on today's single-key, fail-closed path.
fn consider_offer(
    host: &str,
    current: &VerifyingKey,
    metadata: &TrustMetadata,
    offer: &RotationOffer,
) -> Result<Option<RotationState>, String> {
    let current_b64 = encode_key(current);
    let next_b64 = encode_key(&offer.next_key);
    if next_b64 == current_b64 {
        return Err("next_public_key is identical to the current key".to_string());
    }

    // The attestation must be produced by the key we have ALREADY pinned.
    // This is the whole security of the feature: without it, anyone able to
    // answer the capability endpoint could re-pin the deployment at will.
    let message = canonical_rotation_message(host, &current_b64, &next_b64, &offer.not_after)?;
    // `verify_strict` rather than `verify`: it additionally rejects
    // small-order / non-canonical `R`, which costs an honest signer
    // nothing and closes the malleability question outright on the one
    // signature that decides whether a key enters the accepted set.
    current
        .verify_strict(&message, &offer.attestation)
        .map_err(|_| {
            format!(
                "next_key_attestation is not a valid signature by the pinned key {}",
                metadata.fingerprint
            )
        })?;

    // Bounded window, enforced even though the deadline is signed: a
    // deployment must not be able to pin open a two-key state forever.
    let not_after = parse_iso8601_utc(&offer.not_after).ok_or_else(|| {
        format!(
            "next_key_not_after '{}' is not YYYY-MM-DDTHH:MM:SSZ",
            offer.not_after
        )
    })?;
    let now = now_unix_checked().ok_or_else(|| {
        "the system clock is too far in the past to bound a rotation window".to_string()
    })?;
    if not_after <= now {
        return Err(format!(
            "overlap window already closed at {}",
            offer.not_after
        ));
    }
    if not_after - now > MAX_OVERLAP_SECS {
        return Err(format!(
            "overlap window ends {} which is more than {} days out",
            offer.not_after,
            MAX_OVERLAP_SECS / 86_400
        ));
    }

    let next_fingerprint = fingerprint(&offer.next_key);
    match &metadata.rotation {
        // No chaining: one rotation at a time. A second, different next key
        // while an overlap is live would mean three acceptable keys.
        Some(active) if active.next_public_key != next_b64 => Err(format!(
            "a rotation to {} is already in progress until {}",
            active.next_fingerprint, active.not_after
        )),
        // Same key re-advertised: only the deadline may move, and the
        // operator has already been told.
        Some(active) => {
            if active.not_after == offer.not_after {
                return Ok(None);
            }
            Ok(Some(RotationState {
                next_fingerprint,
                next_public_key: next_b64,
                not_after: offer.not_after.clone(),
                accepted_at: now_iso8601(),
                attested_by: current_b64,
                notice_shown: active.notice_shown,
            }))
        }
        None => Ok(Some(RotationState {
            next_fingerprint,
            next_public_key: next_b64,
            not_after: offer.not_after.clone(),
            accepted_at: now_iso8601(),
            attested_by: current_b64,
            notice_shown: false,
        })),
    }
}

/// True when an overlap window is over.
///
/// Every uncertain case counts as expired — an unparseable deadline, an
/// unparseable acceptance time, or a clock the launcher cannot trust. Fail
/// closed: the cost of expiring early is one `--launcher-trust-rotate`, the
/// cost of expiring late is an indefinitely widened accepted key set.
fn overlap_expired(rotation: &RotationState) -> bool {
    let (Some(now), Some(not_after), Some(accepted_at)) = (
        now_unix_checked(),
        parse_iso8601_utc(&rotation.not_after),
        parse_iso8601_utc(&rotation.accepted_at),
    ) else {
        return true;
    };
    // A window cannot have been accepted in our own future. When it looks
    // that way the clock has regressed — a dead RTC falling back to a BIOS
    // date, a VM restored from an older snapshot, a stale NTP reference —
    // and treating the elapsed time as zero would hold the window open
    // indefinitely, which is exactly the unbounded two-key state this
    // module refuses to have. The sanity floor does not catch this on its
    // own: it only rejects clocks below a fixed constant, not clocks below
    // the present.
    if now < accepted_at {
        return true;
    }
    // The deadline is the deployment's; the acceptance bound is ours, and
    // it holds even if the clock is later rolled back behind `not_after`.
    now >= not_after || now - accepted_at >= MAX_OVERLAP_SECS
}

/// The one-time "a rotation is in progress" notice.
fn print_rotation_notice(
    host: &str,
    current_fingerprint: &str,
    rotation: &RotationState,
    advisory_url: Option<&str>,
) {
    eprintln!("{host} is rotating its deployment signing key.");
    eprintln!("  current fingerprint: {current_fingerprint}");
    eprintln!("  next fingerprint:    {}", rotation.next_fingerprint);
    eprintln!("  both accepted until: {}", rotation.not_after);
    eprintln!("  Nothing to do now. If the deployment has not switched over by then,");
    eprintln!("  the window closes and a later switch will fail with a trust violation");
    eprintln!("  until you confirm the new key yourself with:");
    eprintln!("    huitzo --launcher-trust-rotate");
    if let Some(url) = advisory_url {
        eprintln!("  More information: {url}");
    }
}

/// Base64 (standard alphabet, padded) of a key's raw 32 bytes.
///
/// Always recomputed from the decoded key rather than echoed from the
/// wire, so non-canonical base64 cannot change the attested bytes.
pub fn encode_key(key: &VerifyingKey) -> String {
    BASE64.encode(key.as_bytes())
}

/// Canonical byte string a `next_key_attestation` signs over.
///
/// Framed, unlike `capabilities::canonical_signed_message`: see the module
/// doc comment for why the separator-free style is unsafe for these fields.
/// Every component must be non-empty and free of `LF`/`CR`, which makes the
/// framing injective; violating that returns the operator-facing reason the
/// offer is being refused.
pub fn canonical_rotation_message(
    host: &str,
    current_key_b64: &str,
    next_key_b64: &str,
    not_after: &str,
) -> Result<Vec<u8>, String> {
    let fields = [
        ("host", host),
        ("current_public_key", current_key_b64),
        ("next_public_key", next_key_b64),
        ("next_key_not_after", not_after),
    ];
    for (label, value) in fields {
        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            return Err(format!(
                "rotation attestation field '{label}' is empty or contains a line break"
            ));
        }
    }
    // Context + its newline, then each field + its newline.
    let mut out = String::with_capacity(
        ROTATION_CONTEXT.len() + 1 + fields.iter().map(|(_, v)| v.len() + 1).sum::<usize>(),
    );
    out.push_str(ROTATION_CONTEXT);
    out.push('\n');
    for (_, value) in fields {
        out.push_str(value);
        out.push('\n');
    }
    Ok(out.into_bytes())
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
    // The staging name APPENDS `.<pid>.tmp` rather than replacing the
    // extension. `with_extension("tmp")` would map both `<host>.pubkey` and
    // `<host>.json` onto the same `<host>.tmp`, so the two writes for one
    // host could clobber each other's staging file; the pid additionally
    // keeps concurrent launcher processes off each other's. The error path
    // below unlinks the staging file, but a process killed outright leaves
    // one behind — inert, since nothing ever reads `.tmp`.
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        Error::Manifest(format!("trust path {} has no file name", path.display()))
    })?;
    let tmp = path.with_file_name(format!("{name}.{}.tmp", std::process::id()));

    let result = (|| -> Result<(), Error> {
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
    })();
    if result.is_err() {
        // Never leave a half-written staging file behind.
        let _ = fs::remove_file(&tmp);
    }
    result
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

/// Current time as Unix seconds, or 0 if the system clock predates the
/// epoch.
fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Current time as Unix seconds, or `None` when the system clock is too far
/// in the past to be believable (dead RTC, container with no clock source,
/// a deliberate rollback).
///
/// Every rotation decision is time-bounded, so a clock the launcher cannot
/// trust must not silently hold an overlap window open forever. Callers
/// treat `None` as "refuse the rotation".
fn now_unix_checked() -> Option<u64> {
    let now = now_unix();
    (now >= CLOCK_SANITY_FLOOR).then_some(now)
}

fn now_iso8601() -> String {
    // Avoid pulling in chrono just for one timestamp; format the Unix
    // epoch seconds into a minimal "YYYY-MM-DDTHH:MM:SSZ" string via the
    // shared seconds-to-date trick. For trust-file metadata exactness
    // matters less than monotonic ordering, so we accept ~1 s of skew.
    format_unix_iso8601(now_unix())
}

/// Parse exactly `YYYY-MM-DDTHH:MM:SSZ` into Unix seconds.
///
/// Deliberately strict — the inverse of [`format_unix_iso8601`] and
/// nothing else. No offsets, no fractional seconds, no lowercase `z`, no
/// pre-1970 dates. Anything else returns `None`, which every caller treats
/// as "refuse the rotation".
///
/// The inverse holds over the four-digit-year domain, which is the only
/// one this module can reach: the fixed 20-byte shape rejects a year of
/// 10000 or beyond, and a deadline is capped at 90 days out anyway. That
/// rejection is itself fail-closed.
fn parse_iso8601_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let field = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(range)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse::<i64>().ok()
    };
    let (year, month, day) = (field(0..4)?, field(5..7)?, field(8..10)?);
    let (hour, minute, second) = (field(11..13)?, field(14..16)?, field(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    // days_from_civil (Howard Hinnant), the inverse of the civil_from_days
    // used by format_unix_iso8601.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        return None;
    }
    let secs = days as u64 * 86_400 + hour as u64 * 3_600 + minute as u64 * 60 + second as u64;

    // The range checks above cannot reject a day that does not exist in its
    // month ("2026-02-31"), which days_from_civil would silently roll over
    // into the next month. Requiring an exact round-trip through the
    // formatter makes this function a true inverse: any input that is not
    // the canonical rendering of the instant it denotes is refused.
    (format_unix_iso8601(secs) == s).then_some(secs)
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

    // ---- #26: overlap-window rotation -----------------------------------

    fn make_signer() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn deadline_in(secs: i64) -> String {
        format_unix_iso8601((now_unix() as i64 + secs).max(0) as u64)
    }

    /// Build a valid offer: `attestor` signs, `next` is the key offered.
    fn offer_from(
        host: &str,
        current: &VerifyingKey,
        attestor: &SigningKey,
        next: &VerifyingKey,
        not_after: &str,
    ) -> RotationOffer {
        use ed25519_dalek::Signer;
        let msg =
            canonical_rotation_message(host, &encode_key(current), &encode_key(next), not_after)
                .unwrap();
        RotationOffer {
            next_key: *next,
            not_after: not_after.to_string(),
            attestation: attestor.sign(&msg),
        }
    }

    #[test]
    fn parse_iso8601_utc_inverts_the_formatter() {
        for secs in [0u64, 1_779_926_400, 1_000_000_000, 253_370_764_800] {
            let formatted = format_unix_iso8601(secs);
            assert_eq!(parse_iso8601_utc(&formatted), Some(secs), "{formatted}");
        }
    }

    #[test]
    fn parse_iso8601_utc_rejects_non_canonical_forms() {
        for bad in [
            "",
            "2026-09-10",
            "2026-09-10T00:00:00",       // no Z
            "2026-09-10T00:00:00z",      // lowercase
            "2026-09-10T00:00:00+00:00", // offset
            "2026-09-10T00:00:00.000Z",  // fractional
            "2026-13-10T00:00:00Z",      // month 13
            "2026-09-10T24:00:00Z",      // hour 24
            "2026-09-10T00:60:00Z",      // minute 60
            "20x6-09-10T00:00:00Z",      // non-digit
            "1969-12-31T23:59:59Z",      // pre-epoch
        ] {
            assert_eq!(parse_iso8601_utc(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn canonical_rotation_message_is_framed_and_domain_separated() {
        let msg = canonical_rotation_message("h", "cur", "next", "2026-09-10T00:00:00Z").unwrap();
        assert_eq!(
            msg,
            b"huitzo-key-rotation:v1\nh\ncur\nnext\n2026-09-10T00:00:00Z\n"
        );
    }

    #[test]
    fn canonical_rotation_message_framing_removes_boundary_ambiguity() {
        // Unframed, ("ab","cd") and ("a","bcd") concatenate identically —
        // one signature would authorise two different (host, key) pairs.
        let unframed_a = format!("{}{}", "ab", "cd");
        let unframed_b = format!("{}{}", "a", "bcd");
        assert_eq!(unframed_a, unframed_b);

        let framed_a = canonical_rotation_message("ab", "cd", "n", "d").unwrap();
        let framed_b = canonical_rotation_message("a", "bcd", "n", "d").unwrap();
        assert_ne!(framed_a, framed_b);
    }

    #[test]
    fn canonical_rotation_message_rejects_line_breaks_and_empties() {
        assert!(canonical_rotation_message("a\nb", "c", "n", "d").is_err());
        assert!(canonical_rotation_message("a", "c\rd", "n", "d").is_err());
        assert!(canonical_rotation_message("", "c", "n", "d").is_err());
    }

    #[test]
    fn offer_is_ignored_on_first_use() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let pinned = pin_or_load("test.example", &current.verifying_key(), false).unwrap();
        assert!(pinned.first_use);

        let offer = offer_from(
            "test.example",
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(3600),
        );
        let out = apply_rotation("test.example", pinned, Some(&offer), None).unwrap();
        assert!(
            out.metadata.rotation.is_none(),
            "TOFU first contact must not open an overlap window"
        );
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn attested_offer_opens_overlap_and_notifies_once() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let not_after = deadline_in(7 * 86_400);
        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &not_after,
        );

        // Second contact: the offer is now attested by a key already on disk.
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&offer), None).unwrap();
        let rotation = out.metadata.rotation.expect("overlap recorded");
        assert_eq!(rotation.next_public_key, encode_key(&next.verifying_key()));
        assert_eq!(rotation.not_after, not_after);
        assert!(rotation.notice_shown, "notice must be marked as shown");

        // Re-advertising the identical offer must not reset the notice flag
        // and must not rewrite the window.
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&offer), None).unwrap();
        let rotation2 = out.metadata.rotation.expect("overlap still recorded");
        assert_eq!(rotation2.accepted_at, rotation.accepted_at);
        assert!(rotation2.notice_shown);
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn offer_attested_by_wrong_key_is_refused() {
        let _home = temp_home();
        let current = make_signer();
        let attacker = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        // Attacker signs the attestation with a key we never pinned.
        let forged = offer_from(
            host,
            &current.verifying_key(),
            &attacker,
            &next.verifying_key(),
            &deadline_in(7 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&forged), None).unwrap();
        assert!(out.metadata.rotation.is_none());

        // ... and the forged next key stays untrusted.
        let err = pin_or_load(host, &next.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn offer_bound_to_another_host_is_refused() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        pin_or_load("test.example", &current.verifying_key(), false).unwrap();

        // Legitimately attested — but for a different deployment host.
        let offer = offer_from(
            "other.example",
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(7 * 86_400),
        );
        let pinned = pin_or_load("test.example", &current.verifying_key(), false).unwrap();
        let out = apply_rotation("test.example", pinned, Some(&offer), None).unwrap();
        assert!(out.metadata.rotation.is_none());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn offer_outside_the_bounded_window_is_refused() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        for not_after in [deadline_in(-60), deadline_in(120 * 86_400)] {
            let offer = offer_from(
                host,
                &current.verifying_key(),
                &current,
                &next.verifying_key(),
                &not_after,
            );
            let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
            let out = apply_rotation(host, pinned, Some(&offer), None).unwrap();
            assert!(
                out.metadata.rotation.is_none(),
                "accepted out-of-bounds deadline {not_after}"
            );
        }
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn an_offer_naming_the_current_key_is_refused() {
        let _home = temp_home();
        let current = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        // A deployment re-affirming its own key, or a rollout script that
        // computed "next" from the wrong source. There is nothing to
        // rotate to, so no window may be opened.
        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &current.verifying_key(),
            &deadline_in(7 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&offer), None).unwrap();
        assert!(out.metadata.rotation.is_none());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn a_second_different_offer_does_not_chain() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let third = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let not_after = deadline_in(7 * 86_400);
        let first = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &not_after,
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&first), None).unwrap();

        let second = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &third.verifying_key(),
            &not_after,
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&second), None).unwrap();
        let rotation = out.metadata.rotation.unwrap();
        assert_eq!(
            rotation.next_public_key,
            encode_key(&next.verifying_key()),
            "the live overlap must not be replaced by a second offer"
        );
        // The third key is not in the accepted set.
        let err = pin_or_load(host, &third.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn using_the_next_key_promotes_it_and_prunes_the_old() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        let first = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let first_seen = first.metadata.first_seen.clone();

        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(7 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        // Deployment cuts over: a document arrives advertising the next key.
        let pinned = pin_or_load(host, &next.verifying_key(), false).unwrap();
        assert_eq!(pinned.key.as_bytes(), next.verifying_key().as_bytes());
        let out = apply_rotation(host, pinned, None, None).unwrap();
        assert!(out.metadata.rotation.is_none(), "overlap must be pruned");
        assert_eq!(out.metadata.fingerprint, fingerprint(&next.verifying_key()));
        assert_eq!(
            out.metadata.first_seen, first_seen,
            "first_seen describes the deployment, not the key"
        );

        // The pubkey file on disk is now the new key...
        assert_eq!(
            fs::read(dirs::pinned_key_path(host)).unwrap(),
            next.verifying_key().as_bytes()
        );
        // ... and the retired key is refused: no downgrade back to it.
        let err = pin_or_load(host, &current.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn overlap_is_discarded_at_the_deadline() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(7 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        // Rewrite the sidecar as if the window had closed. (Faster and more
        // deterministic than waiting; the expiry path reads only not_after.)
        let mut metadata = load_pinned(host).unwrap().unwrap().metadata;
        metadata.rotation.as_mut().unwrap().not_after = deadline_in(-1);
        write_metadata(host, &metadata).unwrap();

        // The next key is no longer acceptable...
        let err = pin_or_load(host, &next.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        // ... the old key still is, and the expired window is gone from disk.
        let still = pin_or_load(host, &current.verifying_key(), false).unwrap();
        assert!(still.metadata.rotation.is_none());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn unparseable_deadline_on_disk_expires_the_overlap() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(7 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        let mut metadata = load_pinned(host).unwrap().unwrap().metadata;
        metadata.rotation.as_mut().unwrap().not_after = "whenever".to_string();
        write_metadata(host, &metadata).unwrap();

        let err = pin_or_load(host, &next.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn parse_iso8601_utc_rejects_days_that_do_not_exist() {
        for bad in [
            "2026-02-30T00:00:00Z",
            "2026-02-31T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-06-31T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-02-29T00:00:00Z", // 2026 is not a leap year
        ] {
            assert_eq!(parse_iso8601_utc(bad), None, "accepted {bad}");
        }
        // Real leap day still parses.
        assert!(parse_iso8601_utc("2028-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn write_atomic_stages_each_trust_file_under_its_own_name() {
        let _home = temp_home();
        let host = "test.example";
        let key = make_key();
        pin_or_load(host, &key, false).unwrap();

        // `with_extension("tmp")` would map <host>.pubkey and <host>.json
        // onto one staging path; they must not collide.
        let name = |p: &std::path::Path| p.file_name().unwrap().to_str().unwrap().to_string();
        let pid = std::process::id();
        let key_tmp = format!("{}.{pid}.tmp", name(&dirs::pinned_key_path(host)));
        let meta_tmp = format!("{}.{pid}.tmp", name(&dirs::trust_meta_path(host)));
        assert_ne!(key_tmp, meta_tmp);

        // And nothing is left behind after a successful write.
        let leftovers: Vec<_> = fs::read_dir(dirs::trust_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "stray staging files: {leftovers:?}");
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn re_advertising_the_same_key_moves_the_deadline_without_renotifying() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let short = deadline_in(7 * 86_400);
        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &short,
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&offer), None).unwrap();
        assert_eq!(out.metadata.rotation.unwrap().not_after, short);

        // Deployment extends the window, re-attesting over the new deadline.
        let long = deadline_in(30 * 86_400);
        let extended = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &long,
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, Some(&extended), None).unwrap();
        let rotation = out.metadata.rotation.unwrap();
        assert_eq!(rotation.not_after, long);
        assert_eq!(rotation.next_public_key, encode_key(&next.verifying_key()));
        assert!(
            rotation.notice_shown,
            "extending a window must not re-notify the operator"
        );
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn a_stale_acceptance_expires_the_window_even_if_the_deadline_is_future() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(30 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        // Simulate a clock rolled back behind the deadline: accepted_at is
        // now more than MAX_OVERLAP_SECS in the past, so our own bound
        // closes the window regardless of what the deployment signed.
        let mut metadata = load_pinned(host).unwrap().unwrap().metadata;
        metadata.rotation.as_mut().unwrap().accepted_at =
            deadline_in(-(MAX_OVERLAP_SECS as i64) - 60);
        write_metadata(host, &metadata).unwrap();

        let err = pin_or_load(host, &next.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn load_pinned_fingerprint_follows_the_pubkey_file_not_the_sidecar() {
        let _home = temp_home();
        let key = make_key();
        let host = "test.example";
        pin_or_load(host, &key, false).unwrap();

        // Hand-edit the sidecar to claim a different key.
        let mut metadata = load_pinned(host).unwrap().unwrap().metadata;
        metadata.fingerprint = fingerprint(&make_key());
        write_metadata(host, &metadata).unwrap();

        let loaded = load_pinned(host).unwrap().unwrap();
        assert_eq!(loaded.metadata.fingerprint, fingerprint(&key));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn rotation_attested_by_a_superseded_key_is_dropped_on_load() {
        let _home = temp_home();
        let old = make_signer();
        let new = make_signer();
        let third = make_signer();
        let host = "test.example";
        pin_or_load(host, &old.verifying_key(), false).unwrap();

        // `old` legitimately nominates `third` ...
        let offer = offer_from(
            host,
            &old.verifying_key(),
            &old,
            &third.verifying_key(),
            &deadline_in(30 * 86_400),
        );
        let pinned = pin_or_load(host, &old.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        // ... then a concurrent writer replaces the pinned key with `new`
        // without clearing the sidecar. The record is now attested by a key
        // that is no longer pinned, so it must not be honoured.
        write_pinned_key(host, &new.verifying_key()).unwrap();

        let loaded = load_pinned(host).unwrap().unwrap();
        assert!(loaded.metadata.rotation.is_none());
        let err = pin_or_load(host, &third.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn rotation_naming_the_already_pinned_key_is_dropped_on_load() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(30 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        // Simulate a kill between the promotion's two writes: the pubkey
        // file is already the next key, the sidecar still points at it.
        write_pinned_key(host, &next.verifying_key()).unwrap();

        let loaded = load_pinned(host).unwrap().unwrap();
        assert!(
            loaded.metadata.rotation.is_none(),
            "a rotation to the key already pinned is vacuous"
        );
        // Converges silently — no second promotion, no repeated notice.
        let pinned = pin_or_load(host, &next.verifying_key(), false).unwrap();
        let out = apply_rotation(host, pinned, None, None).unwrap();
        assert!(out.metadata.rotation.is_none());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn a_clock_regressed_behind_acceptance_expires_the_window() {
        let _home = temp_home();
        let current = make_signer();
        let next = make_signer();
        let host = "test.example";
        pin_or_load(host, &current.verifying_key(), false).unwrap();

        let offer = offer_from(
            host,
            &current.verifying_key(),
            &current,
            &next.verifying_key(),
            &deadline_in(30 * 86_400),
        );
        let pinned = pin_or_load(host, &current.verifying_key(), false).unwrap();
        apply_rotation(host, pinned, Some(&offer), None).unwrap();

        // The clock regresses to a point AFTER the sanity floor but BEFORE
        // the acceptance — a BIOS fallback date, an older VM snapshot, a
        // stale NTP reference. Modelled by moving `accepted_at` into the
        // future; the deadline is left well ahead, so this check is the
        // only thing that can close the window.
        let mut metadata = load_pinned(host).unwrap().unwrap().metadata;
        let rotation = metadata.rotation.as_mut().unwrap();
        rotation.accepted_at = deadline_in(3_600);
        assert!(
            parse_iso8601_utc(&rotation.not_after).unwrap() > now_unix(),
            "the deadline must still be in the future for this to isolate the clock check"
        );
        write_metadata(host, &metadata).unwrap();

        let err = pin_or_load(host, &next.verifying_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        // The old key keeps working, and the window is gone.
        let still = pin_or_load(host, &current.verifying_key(), false).unwrap();
        assert!(still.metadata.rotation.is_none());
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }

    #[test]
    fn legacy_single_key_sidecar_still_loads() {
        let _home = temp_home();
        let key = make_key();
        pin_or_load("test.example", &key, false).unwrap();

        // Overwrite the sidecar with the exact pre-#26 shape.
        let legacy = format!(
            r#"{{"fingerprint":"{}","first_seen":"2026-01-01T00:00:00Z","issuer":"test.example"}}"#,
            fingerprint(&key)
        );
        fs::write(dirs::trust_meta_path("test.example"), legacy).unwrap();

        let loaded = load_pinned("test.example").unwrap().unwrap();
        assert!(loaded.metadata.rotation.is_none());
        assert_eq!(loaded.metadata.first_seen, "2026-01-01T00:00:00Z");
        // Behaves exactly as before: match passes, mismatch is a violation.
        pin_or_load("test.example", &key, false).unwrap();
        let err = pin_or_load("test.example", &make_key(), false).unwrap_err();
        assert!(matches!(err, Error::TrustViolation { .. }));
        unsafe { std::env::remove_var("HUITZO_HOME") };
    }
}
