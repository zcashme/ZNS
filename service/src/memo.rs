//! Admin Ed25519 memo signing — BUY memos for the Zcash name registry.
//!
//! This is a completely separate operation from the payout.  The admin
//! wallet holds an Ed25519 keypair used only for `BUY` memos.  It never
//! touches escrow funds.
//!
//! BUY memo format (frozen protocol):
//!     ZNS:BUY:<name>:<buyer_ua>:<sig>
//! where <sig> is the base64-encoded Ed25519 signature of:
//!     BUY:<name>:<buyer_ua>

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

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
