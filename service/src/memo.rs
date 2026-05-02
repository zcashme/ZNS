//! BUY memo signing and verification.
//!
//! Sovereign path: buyer signs `BUY:<name>:<buyer_ua>` with their own ed25519
//! key; relayer just verifies and forwards.
//!
//! Admin fallback: if the buyer omits a signature, the relayer signs the same
//! payload with `ZNS_ADMIN_ED25519_KEY` and submits the admin's pubkey as the
//! buyer credentials. The contract treats them identically — any valid
//! ed25519 sig over `BUY:<name>:<buyer_ua>` is accepted. Indexers can decide
//! whether to trust the admin key as a memo signer.
//!
//! On-chain memo wire format (Orchard treasury output):
//!     ZNS:BUY:<name>:<buyer_ua>:<sig_b64>:<pubkey_b64>

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier};

pub struct MemoSigner {
    key: SigningKey,
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

    /// Sign `BUY:<name>:<buyer_ua>` and return the base64-encoded signature
    /// alongside the admin pubkey (also base64). Caller submits both to the
    /// contract as `(buyer_signature_b64, buyer_pubkey_b64)`.
    pub fn sign_buy_credentials(&self, name: &str, buyer_ua: &str) -> (String, String) {
        let payload = format!("BUY:{name}:{buyer_ua}");
        let sig_b64 = base64::engine::general_purpose::STANDARD
            .encode(self.key.sign(payload.as_bytes()).to_bytes());
        (sig_b64, self.pubkey_b64.clone())
    }
}

/// Verify a BUY signature against an arbitrary ed25519 pubkey (buyer's own
/// or the admin's — the contract doesn't distinguish).
pub fn verify_buy_signature(
    name: &str,
    buyer_ua: &str,
    signature_b64: &str,
    pubkey_b64: &str,
) -> bool {
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
