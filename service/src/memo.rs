//! Admin Ed25519 memo signing — BUY memos for the Zcash name registry.
//!
//! When the buyer does not provide their own Ed25519 signature, the admin
//! wallet signs the BUY memo as a fallback. This keeps the indexer compatible
//! with the non-custodial flow while still allowing buyer-side sovereignty.
//!
//! BUY memo format (with admin signature):
//!     ZNS:BUY:<name>:<buyer_ua>:<sig>
//! where <sig> is the base64-encoded Ed25519 signature of:
//!     BUY:<name>:<buyer_ua>
//!
//! Buyer-sovereignty format (optional):
//!     ZNS:BUY:<name>:<buyer_ua>:<buyer_sig>:<buyer_pubkey>

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier};

pub struct MemoSigner {
    key: SigningKey,
    #[allow(dead_code)]
    pubkey_b64: String,
}

impl MemoSigner {
    pub fn from_hex(hex_key: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(hex_key)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("ed25519 key not 32 bytes"))?;
        let key = SigningKey::from_bytes(&key);
        let pubkey_b64 =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        Ok(Self { key, pubkey_b64 })
    }

    /// Sign a BUY memo and return the full wire-format memo string.
    pub fn sign_buy(&self, name: &str, buyer_ua: &str) -> String {
        let payload = format!("BUY:{name}:{buyer_ua}");
        let sig = base64::engine::general_purpose::STANDARD
            .encode(self.key.sign(payload.as_bytes()).to_bytes());
        format!("ZNS:BUY:{name}:{buyer_ua}:{sig}")
    }

    /// Return the base64-encoded public key (used by CLI / explorers).
    #[allow(dead_code)]
    pub fn pubkey(&self) -> &str {
        &self.pubkey_b64
    }
}

/// Verify a buyer-provided BUY signature.
///
/// Returns true if `signature_b64` over `BUY:{name}:{buyer_ua}` validates
/// against the provided base64-encoded Ed25519 public key.
pub fn verify_buy_signature(name: &str, buyer_ua: &str, signature_b64: &str, pubkey_b64: &str) -> bool {
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(pk_bytes) = base64::engine::general_purpose::STANDARD.decode(pubkey_b64) else {
        return false;
    };
    if pk_bytes.len() != 32 {
        return false;
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let payload = format!("BUY:{name}:{buyer_ua}");
    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}
