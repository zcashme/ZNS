//! Key derivation and address parsing for ZNS Schnorr
//!
//! **Public API** (top) — derive keys, parse addresses, verify ownership.
//!
//! **Orchard gap functions** (bottom, private) — reimplement what the orchard
//! crate locks behind `pub(crate)`. These call the same public `pasta_curves`
//! APIs that orchard uses internally:
//! - `diversify_hash` ↔ `orchard::spec::diversify_hash` (pub(crate))
//! - `pk_d_from_address` ↔ `orchard::Address::pk_d()` (pub(crate))
//! - `ivk_to_scalar` ↔ no orchard equivalent (scalar not exposed at all)

use anyhow::{bail, Context, Result};
use bip0039::Mnemonic;
use group::{Group, GroupEncoding};
use orchard::keys::IncomingViewingKey;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use zcash_address::unified::{self, Container, Encoding, Receiver};
use zcash_address::ZcashAddress;
use zcash_protocol::consensus::NetworkType;

const COIN_TYPE: u32 = 133;

// ── Public API ─────────────────────────────────────────────────────────────

/// Derive Orchard IncomingViewingKey from a 24-word BIP39 seed phrase.
///
/// Derivation path: seed → SpendingKey (ZIP 32) → FullViewingKey → IVK
pub fn derive_orchard_ivk_from_seed(phrase: &str) -> Result<IncomingViewingKey> {
    let mnemonic: Mnemonic<bip0039::English> = Mnemonic::from_phrase(phrase.trim())
        .map_err(|e| anyhow::anyhow!("invalid seed phrase: {:?}", e))?;
    let seed = mnemonic.to_seed("");
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, COIN_TYPE, zip32::AccountId::ZERO)
        .map_err(|e| anyhow::anyhow!("failed to derive spending key: {:?}", e))?;
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    Ok(fvk.to_ivk(orchard::keys::Scope::External))
}

/// Parse Orchard IncomingViewingKey from 128-character hex string (64 bytes).
pub fn parse_ivk_hex(hex_str: &str) -> Result<IncomingViewingKey> {
    let hex_clean = hex_str.trim();
    if hex_clean.len() != 128 {
        bail!("Orchard IVK hex must be exactly 128 characters (64 bytes)");
    }
    let bytes = hex::decode(hex_clean).context("invalid hex in IVK")?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("IVK must be 64 bytes"))?;
    parse_orchard_ivk(&arr)
}

/// Parse Orchard IncomingViewingKey from 64-byte raw encoding.
pub fn parse_orchard_ivk(bytes: &[u8; 64]) -> Result<IncomingViewingKey> {
    IncomingViewingKey::from_bytes(bytes)
        .into_option()
        .context("invalid Orchard IVK bytes")
}

/// Serialize Orchard IncomingViewingKey to 64-byte raw encoding.
pub fn orchard_ivk_to_bytes(ivk: &IncomingViewingKey) -> [u8; 64] {
    ivk.to_bytes()
}

/// Serialize IVK to hex string.
pub fn ivk_to_hex(ivk: &IncomingViewingKey) -> String {
    hex::encode(ivk.to_bytes())
}

/// Schnorr components extracted from an Orchard address.
pub struct AddressComponents {
    /// Diversified base point: g_d = DiversifyHash(d).
    /// A public point determined by the diversifier alone — anyone can compute it.
    /// In the Schnorr equation [s]×g_d == R + [c]×pk_d, this is the base point.
    pub g_d: pallas::Point,
    /// Diversified transmission key: pk_d = [ivk] × g_d.
    /// The actual public key in the address. Only the IVK holder can produce
    /// the correct pk_d for a given g_d.
    pub pk_d: pallas::Point,
    /// 11-byte diversifier from the address
    pub diversifier: [u8; 11],
}

/// Extract g_d, pk_d, and diversifier from a unified address.
pub fn extract_address_components(address: &ZcashAddress) -> Result<AddressComponents> {
    let (orchard_addr, _) = parse_orchard_receiver(address)?;
    internal_address_components(&orchard_addr)
}

/// Derive a unified address from an Orchard IncomingViewingKey at diversifier index 0.
///
/// Returns (address_string, g_d, pk_d, diversifier).
/// Uses ivk.address_at() from orchard's public API for derivation.
pub fn derive_unified_address(
    ivk: &IncomingViewingKey,
) -> Result<(String, pallas::Point, pallas::Point, [u8; 11])> {
    let orchard_addr = ivk.address_at(zip32::DiversifierIndex::new());
    let components = internal_address_components(&orchard_addr)?;

    let raw = orchard_addr.to_raw_address_bytes();
    let receivers = vec![Receiver::Orchard(raw)];
    let unified_addr = unified::Address::try_from_items(receivers)
        .map_err(|e| anyhow::anyhow!("failed to create unified address: {:?}", e))?;
    let address_str = unified_addr.encode(&NetworkType::Main);

    Ok((
        address_str,
        components.g_d,
        components.pk_d,
        components.diversifier,
    ))
}

/// Verify that a unified address belongs to a given IVK.
///
/// Strategy: extract the diversifier from the address, then call
/// `ivk.address(d)` (orchard public API) to derive the expected address.
/// If the raw bytes match, the address belongs to this IVK.
///
/// This avoids `ivk_to_scalar` entirely — orchard does the derivation
/// internally and we just compare the outputs.
pub fn verify_address_ownership(
    address: &ZcashAddress,
    ivk: &IncomingViewingKey,
) -> Result<AddressComponents> {
    let (orchard_addr, orchard_bytes) = parse_orchard_receiver(address)?;
    let diversifier = orchard_addr.diversifier();

    let expected_addr = ivk.address(diversifier);
    let expected_bytes = expected_addr.to_raw_address_bytes();

    if orchard_bytes != expected_bytes {
        bail!(
            "Address verification failed: the provided unified address \
             does not belong to the given IVK"
        );
    }

    internal_address_components(&orchard_addr)
}

/// Convert an Orchard IncomingViewingKey to a pallas::Scalar for signing.
pub fn ivk_to_scalar(ivk: &IncomingViewingKey) -> Result<pallas::Scalar> {
    use ff::PrimeField;

    let ivk_bytes = ivk.to_bytes();
    let scalar_bytes: &[u8; 32] = ivk_bytes[32..64]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to extract scalar bytes"))?;

    pallas::Scalar::from_repr(*scalar_bytes)
        .into_option()
        .context("invalid IVK scalar encoding - value may be >= modulus")
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Extract Schnorr components (g_d, pk_d, diversifier) from an orchard::Address.
pub(crate) fn internal_address_components(addr: &orchard::Address) -> Result<AddressComponents> {
    let d_bytes = *addr.diversifier().as_array();
    let g_d = diversify_hash(&d_bytes);
    let pk_d = pk_d_from_address(addr)?;
    Ok(AddressComponents {
        g_d,
        pk_d,
        diversifier: d_bytes,
    })
}

/// Decode a Zcash unified address and extract the Orchard receiver.
fn parse_orchard_receiver(address: &ZcashAddress) -> Result<(orchard::Address, [u8; 43])> {
    let addr_str = address.to_string();
    let (_net, addr_bytes) = unified::Address::decode(&addr_str)
        .map_err(|e| anyhow::anyhow!("failed to decode unified address: {:?}", e))?;

    for item in addr_bytes.items() {
        if let unified::Receiver::Orchard(orchard_bytes) = item {
            let orchard_addr = orchard::Address::from_raw_address_bytes(&orchard_bytes)
                .into_option()
                .context("failed to parse Orchard receiver bytes")?;
            return Ok((orchard_addr, orchard_bytes));
        }
    }

    bail!("unified address has no Orchard receiver")
}

// ── Orchard gap functions ──────────────────────────────────────────────────
const ORCHARD_GD_PERSONALIZATION: &str = "z.cash:Orchard-gd";

/// Compute the diversified base point g_d from an 11-byte diversifier.
fn diversify_hash(d: &[u8; 11]) -> pallas::Point {
    let hasher = pallas::Point::hash_to_curve(ORCHARD_GD_PERSONALIZATION);
    let g_d = hasher(d);
    if bool::from(g_d.is_identity()) {
        hasher(&[])
    } else {
        g_d
    }
}

/// Extract the diversified transmission key pk_d from an orchard::Address.
fn pk_d_from_address(addr: &orchard::Address) -> Result<pallas::Point> {
    let raw = addr.to_raw_address_bytes();
    let pk_d_bytes: &[u8; 32] = raw[11..43]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pk_d length"))?;
    let pk_d_affine = pallas::Affine::from_bytes(pk_d_bytes)
        .into_option()
        .context("invalid pk_d encoding")?;
    Ok(pallas::Point::from(pk_d_affine))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diversify_hash_produces_non_identity() {
        let g_d = diversify_hash(&[1u8; 11]);
        assert!(!bool::from(g_d.is_identity()));
    }

    #[test]
    fn test_diversify_hash_is_deterministic() {
        assert_eq!(diversify_hash(&[1u8; 11]), diversify_hash(&[1u8; 11]));
    }

    #[test]
    fn test_diversify_hash_different_inputs_differ() {
        assert_ne!(diversify_hash(&[1u8; 11]), diversify_hash(&[2u8; 11]));
    }
}
