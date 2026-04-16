//! Ed25519 signature verification for ZNS responses.
//!
//! Implements client-side verification of ZNS records, supporting both
//! admin-signed and sovereign (user-key-signed) registrations. Mirrors
//! `ZNS/src/memo.rs::verify_signature` exactly — if the two ever diverge
//! the client will reject records the indexer accepts (or vice versa).
//!
//! ## The trust boundary
//!
//! Wallets should take [`VerifiedRegistration`] as input for sending,
//! never a plain [`Registration`]. The newtype can only be constructed
//! by [`verify_registration`], so the type system enforces the
//! invariant "this binding was cryptographically proved" at compile
//! time — no runtime check, no forgetting.
//!
//! ## Sovereign vs admin verification
//!
//! A registration with a `pubkey` field was signed by a sovereign user
//! key; verification is performed against that key. A registration
//! without `pubkey` was signed by the admin key; verification is
//! performed against [`AdminPubkey`].
//!
//! ## Typical flow
//!
//! ```ignore
//! let client = Client::new(endpoint);
//! let status = client.status().await?;
//! let admin_pk = AdminPubkey::from_base64(&status.admin_pubkey)?;
//!
//! let reg = client.resolve("alice").await?.ok_or(...)?;
//! let verified = verify_registration(&reg, &admin_pk)?;
//! send_to(&verified.address);
//! ```

use crate::types::{LastAction, Listing, Registration};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::ops::Deref;

/// The 32-byte Ed25519 admin public key used to sign ZNS records.
///
/// Bootstrap from `Client::status().admin_pubkey` via
/// [`AdminPubkey::from_base64`], or construct from raw bytes if you
/// already have them pinned.
#[derive(Debug, Clone, Copy)]
pub struct AdminPubkey([u8; 32]);

impl AdminPubkey {
    /// Parse from the base64-STANDARD encoding returned in
    /// `Status.admin_pubkey`.
    pub fn from_base64(s: &str) -> anyhow::Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| anyhow::anyhow!("admin pubkey base64 decode failed: {e}"))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("admin pubkey must be exactly 32 bytes, got {}", bytes.len())
        })?;
        Ok(Self(arr))
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A [`Registration`] whose Ed25519 signature has been verified against
/// the admin pubkey.
///
/// Can only be constructed via [`verify_registration`]. Wallets that
/// take this type as input for sending get a compile-time guarantee
/// that the name→address binding was cryptographically proved.
///
/// Derefs to the inner [`Registration`] so field access just works:
/// `verified.address`, `verified.nonce`, etc.
#[derive(Debug, Clone)]
pub struct VerifiedRegistration(Registration);

impl Deref for VerifiedRegistration {
    type Target = Registration;
    fn deref(&self) -> &Registration {
        &self.0
    }
}

/// A [`Listing`] whose Ed25519 signature has been verified.
#[derive(Debug, Clone)]
pub struct VerifiedListing(Listing);

impl Deref for VerifiedListing {
    type Target = Listing;
    fn deref(&self) -> &Listing {
        &self.0
    }
}

/// Verify a registration's signature.
///
/// If `reg.pubkey` is present, verifies against the sovereign user key.
/// Otherwise, verifies against the admin pubkey. Reconstructs the signing
/// pre-image from `last_action` and the remaining fields, then checks it
/// with Ed25519. Returns [`VerifiedRegistration`] on success, an error on
/// bad signatures, missing signatures, or key/sig parse failures.
pub fn verify_registration(
    reg: &Registration,
    admin_pubkey: &AdminPubkey,
) -> anyhow::Result<VerifiedRegistration> {
    let sig_b64 = reg.signature.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "registration for '{}' has no signature (legacy pre-signed entry)",
            reg.name
        )
    })?;

    let payload = match reg.last_action {
        LastAction::Claim => format!("CLAIM:{}:{}", reg.name, reg.address),
        LastAction::Update => format!("UPDATE:{}:{}:{}", reg.name, reg.address, reg.nonce),
        LastAction::Delist => format!("DELIST:{}:{}", reg.name, reg.nonce),
        LastAction::Buy => format!("BUY:{}:{}", reg.name, reg.address),
        LastAction::Release => format!("RELEASE:{}:{}", reg.name, reg.nonce),
    };

    if let Some(user_pk_b64) = &reg.pubkey {
        let user_pk = parse_pubkey(user_pk_b64)?;
        verify_bytes_generic(payload.as_bytes(), sig_b64, &user_pk).map_err(|e| {
            anyhow::anyhow!(
                "sovereign signature check failed for registration '{}': {e}",
                reg.name
            )
        })?;
    } else {
        verify_bytes_generic(payload.as_bytes(), sig_b64, admin_pubkey.as_bytes()).map_err(
            |e| {
                anyhow::anyhow!(
                    "admin signature check failed for registration '{}': {e}",
                    reg.name
                )
            },
        )?;
    }

    Ok(VerifiedRegistration(reg.clone()))
}

/// Verify a listing's signature.
///
/// Pre-image is always `"LIST:{name}:{price}:{nonce}"`.
/// If `listing.pubkey` is present, verifies against the sovereign user key.
/// Otherwise, verifies against the admin pubkey.
pub fn verify_listing(
    listing: &Listing,
    admin_pubkey: &AdminPubkey,
) -> anyhow::Result<VerifiedListing> {
    let payload = format!("LIST:{}:{}:{}", listing.name, listing.price, listing.nonce);
    let payload_bytes = payload.as_bytes();

    if let Some(user_pk_b64) = &listing.pubkey {
        let user_pk = parse_pubkey(user_pk_b64)?;
        verify_bytes_generic(payload_bytes, &listing.signature, &user_pk).map_err(|e| {
            anyhow::anyhow!(
                "sovereign signature check failed for listing '{}': {e}",
                listing.name
            )
        })?;
    } else {
        verify_bytes_generic(payload_bytes, &listing.signature, admin_pubkey.as_bytes()).map_err(
            |e| {
                anyhow::anyhow!(
                    "admin signature check failed for listing '{}': {e}",
                    listing.name
                )
            },
        )?;
    }

    Ok(VerifiedListing(listing.clone()))
}

fn parse_pubkey(b64: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("pubkey base64 decode failed: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must be exactly 32 bytes, got {}", bytes.len()))
}

fn verify_bytes_generic(payload: &[u8], sig_b64: &str, pubkey: &[u8; 32]) -> anyhow::Result<()> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("signature parse failed: {e}"))?;
    let vk =
        VerifyingKey::from_bytes(pubkey).map_err(|e| anyhow::anyhow!("invalid pubkey: {e}"))?;
    vk.verify(payload, &sig)
        .map_err(|e| anyhow::anyhow!("ed25519 verify failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_key() -> (SigningKey, AdminPubkey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = AdminPubkey::from_bytes(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn sign_b64(sk: &SigningKey, payload: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(sk.sign(payload).to_bytes())
    }

    fn reg_template(last_action: LastAction, nonce: u64) -> Registration {
        Registration {
            name: "alice".into(),
            address: "utest1alice".into(),
            txid: "txid".into(),
            height: 1000,
            nonce,
            signature: None,
            last_action,
            pubkey: None,
            listing: None,
        }
    }

    #[test]
    fn verifies_claim() {
        let (sk, pk) = test_key();
        let mut reg = reg_template(LastAction::Claim, 0);
        reg.signature = Some(sign_b64(&sk, b"CLAIM:alice:utest1alice"));
        verify_registration(&reg, &pk).unwrap();
    }

    #[test]
    fn verifies_update() {
        let (sk, pk) = test_key();
        let mut reg = reg_template(LastAction::Update, 3);
        reg.signature = Some(sign_b64(&sk, b"UPDATE:alice:utest1alice:3"));
        verify_registration(&reg, &pk).unwrap();
    }

    #[test]
    fn verifies_delist() {
        let (sk, pk) = test_key();
        let mut reg = reg_template(LastAction::Delist, 5);
        reg.signature = Some(sign_b64(&sk, b"DELIST:alice:5"));
        verify_registration(&reg, &pk).unwrap();
    }

    #[test]
    fn verifies_buy() {
        let (sk, pk) = test_key();
        let mut reg = reg_template(LastAction::Buy, 0);
        reg.signature = Some(sign_b64(&sk, b"BUY:alice:utest1alice"));
        verify_registration(&reg, &pk).unwrap();
    }

    #[test]
    fn verifies_release() {
        let (sk, pk) = test_key();
        let mut reg = reg_template(LastAction::Release, 7);
        reg.signature = Some(sign_b64(&sk, b"RELEASE:alice:7"));
        verify_registration(&reg, &pk).unwrap();
    }

    #[test]
    fn verifies_sovereign_claim() {
        let user_sk = SigningKey::from_bytes(&[88u8; 32]);
        let user_pk_bytes = user_sk.verifying_key().to_bytes();
        let user_pk_b64 = base64::engine::general_purpose::STANDARD.encode(user_pk_bytes);
        let (_, admin_pk) = test_key();

        let mut reg = reg_template(LastAction::Claim, 0);
        reg.signature = Some(sign_b64(&user_sk, b"CLAIM:alice:utest1alice"));
        reg.pubkey = Some(user_pk_b64);
        verify_registration(&reg, &admin_pk).unwrap();
    }

    #[test]
    fn sovereign_rejects_wrong_user_key() {
        let user_sk = SigningKey::from_bytes(&[88u8; 32]);
        let other_sk = SigningKey::from_bytes(&[77u8; 32]);
        let other_pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(other_sk.verifying_key().to_bytes());
        let (_, admin_pk) = test_key();

        let mut reg = reg_template(LastAction::Claim, 0);
        reg.signature = Some(sign_b64(&user_sk, b"CLAIM:alice:utest1alice"));
        reg.pubkey = Some(other_pk_b64);
        assert!(verify_registration(&reg, &admin_pk).is_err());
    }

    #[test]
    fn rejects_tampered_address() {
        let (sk, pk) = test_key();
        let sig = sign_b64(&sk, b"CLAIM:alice:utest1REAL");
        let mut reg = reg_template(LastAction::Claim, 0);
        reg.address = "utest1EVIL".into();
        reg.signature = Some(sig);
        assert!(verify_registration(&reg, &pk).is_err());
    }

    #[test]
    fn rejects_wrong_nonce() {
        let (sk, pk) = test_key();
        let sig = sign_b64(&sk, b"UPDATE:alice:utest1alice:3");
        let mut reg = reg_template(LastAction::Update, 4);
        reg.signature = Some(sig);
        assert!(verify_registration(&reg, &pk).is_err());
    }

    #[test]
    fn rejects_missing_signature() {
        let (_, pk) = test_key();
        let reg = reg_template(LastAction::Claim, 0);
        assert!(verify_registration(&reg, &pk).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let (sk, _) = test_key();
        let other_sk = SigningKey::from_bytes(&[99u8; 32]);
        let other_pk = AdminPubkey::from_bytes(other_sk.verifying_key().to_bytes());
        let mut reg = reg_template(LastAction::Claim, 0);
        reg.signature = Some(sign_b64(&sk, b"CLAIM:alice:utest1alice"));
        assert!(verify_registration(&reg, &other_pk).is_err());
    }

    #[test]
    fn rejects_wrong_last_action() {
        let (sk, pk) = test_key();
        // Sign a CLAIM payload but claim it's an UPDATE — pre-image mismatch.
        let mut reg = reg_template(LastAction::Update, 0);
        reg.signature = Some(sign_b64(&sk, b"CLAIM:alice:utest1alice"));
        assert!(verify_registration(&reg, &pk).is_err());
    }

    #[test]
    fn verifies_listing() {
        let (sk, pk) = test_key();
        let listing = Listing {
            name: "bob".into(),
            price: 100_000,
            nonce: 3,
            txid: "txid".into(),
            height: 1001,
            signature: sign_b64(&sk, b"LIST:bob:100000:3"),
            pubkey: None,
        };
        verify_listing(&listing, &pk).unwrap();
    }

    #[test]
    fn rejects_tampered_listing_price() {
        let (sk, pk) = test_key();
        let mut listing = Listing {
            name: "bob".into(),
            price: 100_000,
            nonce: 3,
            txid: "txid".into(),
            height: 1001,
            signature: sign_b64(&sk, b"LIST:bob:100000:3"),
            pubkey: None,
        };
        listing.price = 50_000;
        assert!(verify_listing(&listing, &pk).is_err());
    }

    #[test]
    fn admin_pubkey_base64_roundtrip() {
        let raw = [7u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let parsed = AdminPubkey::from_base64(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), &raw);
    }

    #[test]
    fn admin_pubkey_wrong_length_rejects() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(AdminPubkey::from_base64(&b64).is_err());
    }

    #[test]
    fn admin_pubkey_invalid_base64_rejects() {
        assert!(AdminPubkey::from_base64("!!!not-base64!!!").is_err());
    }
}
