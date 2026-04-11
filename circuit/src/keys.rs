//! Key derivation and address parsing for ZNS Schnorr
//!
//! Handles:
//! - Seed phrase → ivk derivation
//! - Unified address parsing → (g_d, pk_d) extraction
//! - IVK hex encoding/decoding

use anyhow::{bail, Context, Result};
use bip0039::Mnemonic;
use ff::{Field, FromUniformBytes, PrimeField};
use group::GroupEncoding;
use zcash_address::ZcashAddress;

use crate::{diversify_hash, Fr, Point};

/// Derive ivk from a 24-word BIP39 seed phrase
///
/// # Arguments
/// * `phrase` - 24-word seed phrase
///
/// # Returns
/// The incoming viewing key (ivk) as a Pallas scalar
pub fn derive_ivk_from_seed(phrase: &str) -> Result<Fr> {
    // Parse mnemonic
    let mnemonic: Mnemonic<bip0039::English> = Mnemonic::from_phrase(phrase.trim())
        .map_err(|e| anyhow::anyhow!("invalid seed phrase: {:?}", e))?;

    // Derive seed from mnemonic
    let seed = mnemonic.to_seed("");

    // For now, we use a simplified derivation
    // In production, this should follow Zcash's full derivation path:
    // seed → spending key → ivk (with proper ZIP 32 derivation)
    //
    // This is a placeholder that hashes the seed to get ivk
    // TODO: Use proper Orchard key derivation once orchard crate integration is complete
    let hash_result = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ZNS:ivk_derive")
        .hash(&seed);
    let hash = hash_result.as_array();

    // Reduce to scalar field using from_uniform_bytes (64 bytes -> Fr)
    let ivk = Fr::from_uniform_bytes(hash);

    // Ensure ivk is non-zero (valid key)
    if ivk.is_zero().into() {
        bail!("derived ivk is zero (invalid key)");
    }

    Ok(ivk)
}

/// Parse ivk from 64-character hex string
///
/// # Arguments
/// * `hex_str` - 64 hex characters representing 32 bytes
///
/// # Returns
/// The ivk as a Pallas scalar
pub fn parse_ivk_hex(hex_str: &str) -> Result<Fr> {
    let hex_clean = hex_str.trim();

    if hex_clean.len() != 64 {
        bail!("ivk hex must be exactly 64 characters (32 bytes)");
    }

    let bytes = hex::decode(hex_clean).context("invalid hex in ivk")?;

    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ivk must be 32 bytes"))?;

    let ivk = Fr::from_repr(arr)
        .into_option()
        .context("ivk bytes are not a valid scalar")?;

    if ivk.is_zero().into() {
        bail!("ivk cannot be zero");
    }

    Ok(ivk)
}

/// Extract g_d and pk_d from a unified address
///
/// Unified addresses contain multiple receivers (transparent, Sapling, Orchard).
/// This extracts the Orchard receiver's components.
///
/// # Arguments
/// * `address` - Parsed Zcash unified address
///
/// # Returns
/// * `g_d` - Diversified base point
/// * `pk_d` - Transmission key
pub fn extract_address_components(address: &ZcashAddress) -> Result<(Point, Point)> {
    use zcash_address::unified::{self, Container, Encoding};

    // Decode as unified address
    let addr_str = address.to_string();
    let (_net, addr_bytes) = unified::Address::decode(&addr_str)
        .map_err(|e| anyhow::anyhow!("failed to decode unified address: {:?}", e))?;

    // Look for Orchard receiver
    for item in addr_bytes.items() {
        if let unified::Receiver::Orchard(orchard_bytes) = item {
            // Orchard receiver is 43 bytes:
            // - 1 byte: flags (not used here)
            // - 11 bytes: diversifier d
            // - 32 bytes: compressed pk_d

            if orchard_bytes.len() < 43 {
                bail!("invalid Orchard receiver length");
            }

            // Extract diversifier (bytes 1-11)
            let d: [u8; 11] = orchard_bytes[1..12].try_into().unwrap();

            // Extract pk_d (bytes 12-43)
            let pk_d_bytes: [u8; 32] = orchard_bytes[12..44].try_into().unwrap();

            // Compute g_d from diversifier
            let g_d = diversify_hash(&d);

            // Parse pk_d using GroupEncoding trait
            let pk_d_repr = pasta_curves::pallas::Affine::from_bytes(&pk_d_bytes);
            let pk_d_affine = pk_d_repr.into_option().context("invalid pk_d encoding")?;
            let pk_d = Point::from(pk_d_affine);

            return Ok((g_d, pk_d));
        }
    }

    bail!("unified address has no Orchard receiver")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ivk_hex_roundtrip() {
        let ivk = Fr::from(123456u64);
        let bytes = ivk.to_repr();
        let hex = hex::encode(bytes);

        let parsed = parse_ivk_hex(&hex).unwrap();
        assert_eq!(ivk, parsed);
    }

    #[test]
    fn test_ivk_hex_invalid_length() {
        let result = parse_ivk_hex("abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_ivk_hex_invalid_chars() {
        let result =
            parse_ivk_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(result.is_err());
    }
}
