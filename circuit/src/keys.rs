//! Key derivation and address parsing for ZNS Schnorr
//!
//! Uses proper Orchard types from the orchard crate:
//! - IncomingViewingKey for IVK operations
//! - Address for Orchard payment addresses
//! - Proper ZIP 32 derivation from seed phrases
//! - Correct DiversifyHash (hash_to_curve with "z.cash:Orchard-gd", not BLAKE2b)

use anyhow::{bail, Context, Result};
use bip0039::Mnemonic;
use group::{Group, GroupEncoding};
use orchard::keys::IncomingViewingKey;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use zcash_address::unified::{self, Container, Encoding, Receiver};
use zcash_address::ZcashAddress;
use zcash_protocol::consensus::NetworkType;

/// Orchard diversifier personalization for hash-to-curve
const ORCHARD_GD_PERSONALIZATION: &str = "z.cash:Orchard-gd";

/// Zcash mainnet coin type for ZIP 32
const COIN_TYPE: u32 = 133;

/// Compute g_d from a diversifier using proper Orchard DiversifyHash
///
/// In Orchard, g_d = DiversifyHash(d) which uses hash_to_curve with
/// personalization "z.cash:Orchard-gd".
/// This is NOT a simple BLAKE2b hash.
pub fn diversify_hash(d: &[u8; 11]) -> pallas::Point {
    let hasher = pallas::Point::hash_to_curve(ORCHARD_GD_PERSONALIZATION);
    let g_d = hasher(d);

    // If the identity occurs, we replace it with a different fixed point.
    // This matches the orchard crate's behavior.
    if bool::from(g_d.is_identity()) {
        hasher(&[])
    } else {
        g_d
    }
}

/// Derive Orchard IncomingViewingKey from a 24-word BIP39 seed phrase
///
/// Uses proper ZIP 32 derivation: seed → spending key → FVK → IVK
///
/// # Arguments
/// * `phrase` - 24-word seed phrase
///
/// # Returns
/// The Orchard IncomingViewingKey
pub fn derive_orchard_ivk_from_seed(phrase: &str) -> Result<IncomingViewingKey> {
    // Parse mnemonic
    let mnemonic: Mnemonic<bip0039::English> = Mnemonic::from_phrase(phrase.trim())
        .map_err(|e| anyhow::anyhow!("invalid seed phrase: {:?}", e))?;

    // Derive seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Use orchard's SpendingKey::from_zip32_seed for proper ZIP 32 derivation
    // This derives: seed → spending key → FVK → IVK
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, COIN_TYPE, zip32::AccountId::ZERO)
        .map_err(|e| anyhow::anyhow!("failed to derive spending key: {:?}", e))?;

    // Derive full viewing key and then incoming viewing key
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ivk = fvk.to_ivk(orchard::keys::Scope::External);

    Ok(ivk)
}

/// Parse Orchard IncomingViewingKey from 64-byte raw encoding (ZIP 316 format)
///
/// # Arguments
/// * `bytes` - 64-byte raw IVK encoding
///
/// # Returns
/// The Orchard IncomingViewingKey
pub fn parse_orchard_ivk(bytes: &[u8; 64]) -> Result<IncomingViewingKey> {
    IncomingViewingKey::from_bytes(bytes)
        .into_option()
        .context("invalid Orchard IVK bytes")
}

/// Serialize Orchard IncomingViewingKey to 64-byte raw encoding
pub fn orchard_ivk_to_bytes(ivk: &IncomingViewingKey) -> [u8; 64] {
    ivk.to_bytes()
}

/// Extract g_d and pk_d from a unified address using proper Orchard types
///
/// Unified addresses contain multiple receivers (transparent, Sapling, Orchard).
/// This extracts the Orchard receiver's components.
///
/// # Arguments
/// * `address` - Parsed Zcash unified address
///
/// # Returns
/// * `g_d` - Diversified base point (pallas::Point)
/// * `pk_d` - Transmission key (pallas::Point)
/// * `diversifier` - The 11-byte diversifier
pub fn extract_address_components(
    address: &ZcashAddress,
) -> Result<(pallas::Point, pallas::Point, [u8; 11])> {
    // Decode as unified address
    let addr_str = address.to_string();
    let (_net, addr_bytes) = unified::Address::decode(&addr_str)
        .map_err(|e| anyhow::anyhow!("failed to decode unified address: {:?}", e))?;

    // Look for Orchard receiver
    for item in addr_bytes.items() {
        if let unified::Receiver::Orchard(orchard_bytes) = item {
            // Parse the Orchard receiver bytes using orchard crate's Address type
            // Address::from_raw_address_bytes is the public API for parsing raw bytes
            // The function signature is from_raw_address_bytes(bytes: &[u8; 43])
            let orchard_addr = orchard::Address::from_raw_address_bytes(&orchard_bytes)
                .into_option()
                .context("failed to parse Orchard receiver bytes")?;

            // Extract diversifier
            let diversifier = orchard_addr.diversifier();
            let d_bytes = *diversifier.as_array();

            // Compute g_d using proper DiversifyHash (hash_to_curve)
            let g_d = diversify_hash(&d_bytes);

            // Extract pk_d from the raw address bytes
            // Orchard raw address format: [d (11 bytes) || pk_d (32 bytes)]
            let pk_d_bytes: &[u8; 32] = orchard_bytes[11..43]
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid pk_d length in address"))?;
            let pk_d_affine = pallas::Affine::from_bytes(pk_d_bytes)
                .into_option()
                .context("invalid pk_d encoding in address")?;
            let pk_d = pallas::Point::from(pk_d_affine);

            return Ok((g_d, pk_d, d_bytes));
        }
    }

    bail!("unified address has no Orchard receiver")
}

/// Derive unified address from Orchard IncomingViewingKey
///
/// Generates a unified address at the first valid diversifier index (0).
/// Uses proper Orchard address derivation.
///
/// # Arguments
/// * `ivk` - Orchard incoming viewing key
///
/// # Returns
/// * `address_str` - Unified address string
/// * `g_d` - Diversified base point
/// * `pk_d` - Transmission key
/// * `diversifier` - The 11-byte diversifier
pub fn derive_unified_address(
    ivk: &IncomingViewingKey,
) -> Result<(String, pallas::Point, pallas::Point, [u8; 11])> {
    // Find the first valid diversifier (starting at index 0)
    // Orchard scans for a valid diversifier starting from DiversifierIndex 0
    let diversifier_index = zip32::DiversifierIndex::new();
    let orchard_addr = ivk.address_at(diversifier_index);

    // Extract the diversifier
    let diversifier = orchard_addr.diversifier();
    let d_bytes = *diversifier.as_array();

    // Compute g_d using proper DiversifyHash
    let g_d = diversify_hash(&d_bytes);

    // Extract pk_d from the raw address bytes
    // Orchard raw address format: [d (11 bytes) || pk_d (32 bytes)]
    let orchard_bytes = orchard_addr.to_raw_address_bytes();
    let pk_d_bytes: &[u8; 32] = orchard_bytes[11..43]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pk_d length"))?;
    let pk_d_affine = pallas::Affine::from_bytes(pk_d_bytes)
        .into_option()
        .context("invalid pk_d encoding")?;
    let pk_d = pallas::Point::from(pk_d_affine);

    // Create the unified address
    let receivers = vec![Receiver::Orchard(orchard_bytes)];
    let unified_addr = unified::Address::try_from_items(receivers)
        .map_err(|e| anyhow::anyhow!("failed to create unified address: {:?}", e))?;

    // Encode with proper network type
    let address_str = unified_addr.encode(&NetworkType::Main);

    Ok((address_str, g_d, pk_d, d_bytes))
}

/// Verify that a unified address belongs to a given IVK
///
/// This checks that pk_d = [ivk] * g_d for the extracted address components.
///
/// The key insight: we don't need to scan diversifier indices. Given an address,
/// we extract d and pk_d. Then compute g_d = DiversifyHash(d), and verify
/// that pk_d = g_d * ivk. The IVK is a scalar, so this is just point multiplication.
pub fn verify_address_ownership(
    address: &ZcashAddress,
    ivk: &IncomingViewingKey,
) -> Result<(pallas::Point, pallas::Point, [u8; 11])> {
    let (g_d, pk_d, diversifier) = extract_address_components(address)?;

    // Convert IVK to scalar for point multiplication
    // IncomingViewingKey.to_bytes() returns 64 bytes (serialized ivk)
    // We need to derive the scalar that when multiplied by g_d gives pk_d
    //
    // The relationship is: pk_d = g_d * ivk_scalar
    // where ivk_scalar is the underlying scalar of the IncomingViewingKey
    //
    // Orchard's IncomingViewingKey internally contains a scalar, but it's not
    // directly exposed. We can derive it by using the fact that:
    // ivk_scalar = hash_to_scalar(ivk_bytes) mod r
    let ivk_scalar = ivk_to_scalar(ivk)?;

    // Compute expected pk_d = g_d * ivk_scalar
    let expected_pk_d = g_d * ivk_scalar;

    // Verify pk_d matches
    if pk_d != expected_pk_d {
        bail!(
            "Address verification failed: the provided unified address does not belong to the given IVK.\n\
             Expected pk_d = {}, got pk_d = {}",
            hex::encode(expected_pk_d.to_bytes()),
            hex::encode(pk_d.to_bytes())
        );
    }

    Ok((g_d, pk_d, diversifier))
}

/// Convert an Orchard IncomingViewingKey to a pallas::Scalar
///
/// The IncomingViewingKey contains:
/// - dk: DiversifierKey (32 bytes, bytes 0-31)
/// - ivk: KeyAgreementPrivateKey wrapping a NonZeroPallasScalar (32 bytes, bytes 32-63)
///
/// Per Zcash Protocol Spec § 5.6.4.3, the raw encoding is:
/// [dk (32 bytes) || ivk_scalar_repr (32 bytes)]
///
/// We extract the ivk scalar from bytes 32-63.
pub fn ivk_to_scalar(ivk: &IncomingViewingKey) -> Result<pallas::Scalar> {
    use ff::PrimeField;

    let ivk_bytes = ivk.to_bytes();

    // The scalar is in bytes 32-63 (the ivk component)
    let scalar_bytes: &[u8; 32] = ivk_bytes[32..64]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to extract scalar bytes"))?;

    // Convert bytes to scalar using PrimeField::from_repr
    // This interprets as little-endian and checks it's a valid scalar
    let scalar = pallas::Scalar::from_repr(*scalar_bytes)
        .into_option()
        .context("invalid IVK scalar encoding - value may be >= modulus")?;

    Ok(scalar)
}

/// Parse IVK from 64-character hex string
///
/// # Arguments
/// * `hex_str` - 128 hex characters representing 64 bytes
///
/// # Returns
/// The Orchard IncomingViewingKey
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

/// Serialize IVK to hex string
pub fn ivk_to_hex(ivk: &IncomingViewingKey) -> String {
    hex::encode(ivk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_diversify_hash() {
        // Test that diversify_hash produces a valid point
        let d = [1u8; 11];
        let g_d = diversify_hash(&d);

        // g_d should not be the identity
        assert!(!bool::from(g_d.is_identity()));
    }

    #[test]
    fn test_diversify_hash_deterministic() {
        // Same diversifier should produce same g_d
        let d = [1u8; 11];
        let g_d1 = diversify_hash(&d);
        let g_d2 = diversify_hash(&d);
        assert_eq!(g_d1, g_d2);
    }

    #[test]
    fn test_diversify_hash_different() {
        // Different diversifiers should (very likely) produce different g_d
        let d1 = [1u8; 11];
        let d2 = [2u8; 11];
        let g_d1 = diversify_hash(&d1);
        let g_d2 = diversify_hash(&d2);
        assert_ne!(g_d1, g_d2);
    }

    #[test]
    fn test_diversifier_creation() {
        let d_bytes = [1u8; 11];
        let diversifier = Diversifier::from_bytes(d_bytes);
        assert_eq!(diversifier.as_array(), &d_bytes);
    }
}
