//! Burner transparent address derivation.
//!
//! Mirrors the NEAR Chain-Signatures epsilon-tweak scheme used by `v1.signer`.
//! The MPC public key is always provided in NEAR canonical format:
//!
//!     secp256k1:<base58>
//!
//! NEAR uses base58 for all public-key encoding because it is URL-safe,
//! avoids visually ambiguous characters (0, O, l, 1), and fits the same
//! space-efficiently as base64 without needing padding or URL-escaping.
//! The raw uncompressed point is 64 bytes (X || Y) — the `0x04` prefix is
//! stripped by NEAR and is re-added here before secp256k1 parsing.
//!
//! Epsilon derivation (matching v1.signer-prod.testnet / v1.signer mainnet):
//!   epsilon  = sha3_256("near-mpc-recovery v0.1.0 epsilon derivation:" || predecessor || "," || path)
//!   child_pk = root_pk + epsilon * G

use anyhow::{Context, Result, bail};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

const EPSILON_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub struct BurnerAddress {
    pub taddr: String,
    pub path: String,
    pub public_key: [u8; 33],
}

/// Derive a deterministic burner transparent Zcash address for an intent.
///
/// * `mpc_root_pubkey` — **must** be the NEAR `secp256k1:<base58>` string returned by
///   `near view v1.signer public_key`.  No other format is accepted.
/// * `predecessor_account_id` — the NEAR account that will call `sign` (the service's
///   NEAR account). The MPC includes this in the epsilon tweak.
/// * `path` — the per-intent derivation path (free-form string in chain-sigs).
pub fn derive_burner(
    mpc_root_pubkey: &str,
    predecessor_account_id: &str,
    path: &str,
    network: &str,
) -> Result<BurnerAddress> {
    let net = match network {
        "mainnet" => NetworkType::Main,
        "testnet" | "regtest" => NetworkType::Test,
        _ => bail!("network must be mainnet or testnet"),
    };

    let root_pk = parse_near_pubkey(mpc_root_pubkey).context("parse mpc root pubkey")?;

    // epsilon = sha3_256(prefix || predecessor || "," || path)
    let mut hasher = Sha3_256::new();
    hasher.update(EPSILON_PREFIX.as_bytes());
    hasher.update(predecessor_account_id.as_bytes());
    hasher.update(b",");
    hasher.update(path.as_bytes());
    let epsilon: [u8; 32] = hasher.finalize().into();

    // child_pk = root_pk + epsilon * G
    let secp = Secp256k1::new();
    let epsilon_sk = SecretKey::from_slice(&epsilon).context("epsilon scalar invalid")?;
    let epsilon_g = PublicKey::from_secret_key(&secp, &epsilon_sk);
    let child_pk = root_pk
        .combine(&epsilon_g)
        .context("combine root_pk with epsilon*G")?;

    let child_compressed = child_pk.serialize();

    // P2PKH: hash160(compressed_pubkey)
    let sha = Sha256::digest(child_compressed);
    let hash160: [u8; 20] = Ripemd160::digest(sha).into();

    let taddr = ZcashAddress::from_transparent_p2pkh(net, hash160).encode();

    Ok(BurnerAddress {
        taddr,
        path: path.to_string(),
        public_key: child_compressed,
    })
}

fn parse_near_pubkey(input: &str) -> Result<PublicKey> {
    let b58 = input.strip_prefix("secp256k1:").with_context(|| {
        format!(
            "MPC pubkey must start with 'secp256k1:' (NEAR canonical base58 format); got: {input}",
        )
    })?;

    let mut bytes = bs58::decode(b58)
        .into_vec()
        .with_context(|| "decode base58 pubkey")?;

    // NEAR *always* stores the uncompressed point as 64 bytes (X || Y).
    // Prepend the 0x04 prefix so secp256k1 can parse it.
    if bytes.len() == 64 {
        let mut uncompressed = vec![0x04u8];
        uncompressed.append(&mut bytes);
        PublicKey::from_slice(&uncompressed).with_context(|| "invalid secp256k1 pubkey bytes")
    } else {
        bail!(
            "expected 64-byte uncompressed point from NEAR (got {} bytes); \
             the base58 payload size changed",
            bytes.len()
        )
    }
}

/// Verify that the transparent payment amount covers the listed price plus a fee reserve.
pub fn verify_sufficient_payment(
    utxo_value: u64,
    listed_price_zat: u64,
    fee_reserve_zat: u64,
    min_confirmations: u32,
    utxo_confirmation: u32,
) -> bool {
    utxo_confirmation >= min_confirmations && utxo_value >= listed_price_zat + fee_reserve_zat
}

/// Build a 25-byte P2PKH scriptPubKey from a compressed secp256k1 pubkey.
pub fn p2pkh_script(pubkey: &[u8; 33]) -> Vec<u8> {
    let sha = Sha256::digest(pubkey);
    let hash160: [u8; 20] = Ripemd160::digest(sha).into();
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&hash160);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}
