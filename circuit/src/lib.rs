//! Pallas curve Schnorr signatures for ZNS name binding authorization
//!
//! The primary API is:
//! - `sign_with_ivk()` — sign using an IncomingViewingKey and diversifier index
//! - `verify_with_address()` — verify using a ZcashAddress

use anyhow::Context;
use blake2b_simd::Params;
use ff::{Field, FromUniformBytes, PrimeField};
use group::GroupEncoding;
use orchard::keys::IncomingViewingKey;
use pasta_curves::pallas;
use rand::RngCore;

pub type Fr = pallas::Scalar;
pub type Point = pallas::Point;

pub mod keys;

pub use keys::AddressComponents;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub r_point: Point,
    pub s_scalar: Fr,
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        let r_compressed = self.r_point.to_bytes();
        result[0..32].copy_from_slice(&r_compressed);
        let s_bytes = self.s_scalar.to_repr();
        result[32..64].copy_from_slice(s_bytes.as_ref());
        result
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> anyhow::Result<Self> {
        let r_bytes: &[u8; 32] = bytes[0..32].try_into().unwrap();
        let r_point = Point::from_bytes(r_bytes)
            .into_option()
            .context("invalid R point encoding")?;

        let s_bytes: &[u8; 32] = bytes[32..64].try_into().unwrap();
        let s_scalar = Fr::from_repr(*s_bytes)
            .into_option()
            .context("invalid s scalar encoding")?;

        Ok(Signature { r_point, s_scalar })
    }
}

pub fn compute_binding_hash(name: &str, address: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(name.as_bytes());
    input.extend_from_slice(address.as_bytes());

    let hash = Params::new()
        .hash_length(32)
        .personal(b"ZNS:sign_bind")
        .hash(&input);

    hash.as_bytes().try_into().unwrap()
}

fn compute_challenge(r_point: &Point, pk_d: &Point, binding_hash: &[u8; 32]) -> Fr {
    let r_compressed = r_point.to_bytes();
    let pk_d_compressed = pk_d.to_bytes();

    let mut c_input = Vec::with_capacity(96);
    c_input.extend_from_slice(&r_compressed);
    c_input.extend_from_slice(&pk_d_compressed);
    c_input.extend_from_slice(binding_hash);

    let c_raw = Params::new()
        .hash_length(64)
        .personal(b"ZNS:sign_chall")
        .hash(&c_input);

    let c_raw_arr: &[u8; 64] = c_raw.as_array();
    Fr::from_uniform_bytes(c_raw_arr)
}

/// Sign a name binding using an Orchard IncomingViewingKey.
///
/// Derives the address at the given diversifier index, extracts
/// the required components, and produces a Schnorr signature.
pub fn sign_with_ivk<R: RngCore>(
    rng: &mut R,
    ivk: &IncomingViewingKey,
    diversifier_index: zip32::DiversifierIndex,
    name: &str,
    address_str: &str,
) -> anyhow::Result<Signature> {
    let orchard_addr = ivk.address_at(diversifier_index);
    let components = keys::internal_address_components(&orchard_addr)?;
    let ivk_scalar = keys::ivk_to_scalar(ivk)?;

    Ok(sign(
        rng,
        &ivk_scalar,
        &components.g_d,
        &components.pk_d,
        name,
        address_str,
    ))
}

/// Verify a Schnorr signature against a ZcashAddress.
///
/// Extracts g_d and pk_d from the address internally.
pub fn verify_with_address(
    address: &zcash_address::ZcashAddress,
    name: &str,
    signature: &Signature,
) -> anyhow::Result<bool> {
    let components = keys::extract_address_components(address)?;
    Ok(verify(
        &components.g_d,
        &components.pk_d,
        name,
        &address.to_string(),
        signature,
    ))
}

/// Low-level Schnorr sign on raw points.
pub fn sign<R: RngCore>(
    rng: &mut R,
    ivk: &Fr,
    g_d: &Point,
    pk_d: &Point,
    name: &str,
    address: &str,
) -> Signature {
    let r = Fr::random(rng);
    let r_point = *g_d * r;
    let binding_hash = compute_binding_hash(name, address);
    let c = compute_challenge(&r_point, pk_d, &binding_hash);
    let s_scalar = r + (c * ivk);

    Signature { r_point, s_scalar }
}

/// Low-level Schnorr verify on raw points.
pub fn verify(g_d: &Point, pk_d: &Point, name: &str, address: &str, signature: &Signature) -> bool {
    let binding_hash = compute_binding_hash(name, address);
    let c = compute_challenge(&signature.r_point, pk_d, &binding_hash);
    let lhs = *g_d * signature.s_scalar;
    let rhs = signature.r_point + (*pk_d * c);
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::Group;
    use rand::thread_rng;

    #[test]
    fn test_signature_roundtrip() {
        let mut rng = thread_rng();
        let ivk = Fr::random(&mut rng);
        let r_test = Fr::random(&mut rng);
        let g_d = Point::generator() * r_test;
        let pk_d = g_d * ivk;

        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, "alice", "u1testaddress123");
        assert!(verify(&g_d, &pk_d, "alice", "u1testaddress123", &sig));
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = thread_rng();
        let ivk = Fr::random(&mut rng);
        let g_d = Point::generator();
        let pk_d = g_d * ivk;

        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, "test", "u1test");
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64);

        let sig2 = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.r_point, sig2.r_point);
        assert_eq!(sig.s_scalar, sig2.s_scalar);
    }

    #[test]
    fn test_wrong_name_fails() {
        let mut rng = thread_rng();
        let ivk = Fr::random(&mut rng);
        let g_d = Point::generator();
        let pk_d = g_d * ivk;

        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, "alice", "u1test");
        assert!(!verify(&g_d, &pk_d, "bob", "u1test", &sig));
    }

    #[test]
    fn test_wrong_address_fails() {
        let mut rng = thread_rng();
        let ivk = Fr::random(&mut rng);
        let g_d = Point::generator();
        let pk_d = g_d * ivk;

        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, "alice", "u1test");
        assert!(!verify(&g_d, &pk_d, "alice", "u1other", &sig));
    }
}
