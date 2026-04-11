//! Pallas curve Schnorr signatures for ZNS name binding authorization
//!
//! This crate implements Schnorr signatures on the Pallas curve (Zcash Orchard).
//! The signature binds a user-defined name to a Zcash unified address,
//! proving knowledge of the incoming viewing key (ivk).
//!
//! Uses proper Orchard types for correct DiversifyHash and key derivation.

use anyhow::Context;
use blake2b_simd::Params;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{Group, GroupEncoding};
use pasta_curves::pallas;
use rand::RngCore;
use std::fmt;

/// Pallas base field (Fp) - for point coordinates
pub type Fq = pallas::Base;
/// Pallas scalar field (Fq) - for ivk scalar
pub type Fr = pallas::Scalar;
/// Pallas point
pub type Point = pallas::Point;
/// Pallas affine point
pub type Affine = pallas::Affine;

/// Key derivation utilities using proper Orchard types
pub mod keys;

// Re-export orchard types for convenience
pub use orchard::keys::IncomingViewingKey;

/// A Schnorr signature: (R, s)
#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// Commitment point R = [r] × g_d
    pub r_point: Point,
    /// Response s = r + c × ivk
    pub s_scalar: Fr,
}

impl Signature {
    /// Serialize signature to bytes (R compressed || s)
    /// Total: 64 bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];

        // Compress R point (32 bytes)
        let r_compressed = self.r_point.to_bytes();
        result[0..32].copy_from_slice(&r_compressed);

        // s scalar (32 bytes, little-endian)
        let s_bytes = self.s_scalar.to_repr();
        result[32..64].copy_from_slice(s_bytes.as_ref());

        result
    }

    /// Deserialize signature from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> anyhow::Result<Self> {
        // Parse R point
        let r_bytes: &[u8; 32] = bytes[0..32].try_into().unwrap();
        let r_option = Point::from_bytes(r_bytes);
        let r_point = r_option.into_option().context("invalid R point encoding")?;

        // Parse s scalar
        let s_bytes: &[u8; 32] = bytes[32..64].try_into().unwrap();
        let s_option = Fr::from_repr(*s_bytes);
        let s_scalar = s_option
            .into_option()
            .context("invalid s scalar encoding")?;

        Ok(Signature { r_point, s_scalar })
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

/// Compute BLAKE2b-256 hash with domain separator for binding
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

/// Compute challenge c = Hash(R || pk_d || binding_hash) mod r
fn compute_challenge(r_point: &Point, pk_d: &Point, binding_hash: &[u8; 32]) -> Fr {
    // Compress points
    let r_compressed = r_point.to_bytes();
    let pk_d_compressed = pk_d.to_bytes();

    // Build input: R || pk_d || binding_hash (32 + 32 + 32 = 96 bytes)
    let mut c_input = Vec::with_capacity(96);
    c_input.extend_from_slice(&r_compressed);
    c_input.extend_from_slice(&pk_d_compressed);
    c_input.extend_from_slice(binding_hash);

    // Hash with personalization (max 16 bytes for blake2b)
    let c_raw = Params::new()
        .hash_length(64)
        .personal(b"ZNS:sign_chall")
        .hash(&c_input);

    // Reduce 512-bit hash to scalar field
    let c_raw_arr: &[u8; 64] = c_raw.as_array();
    Fr::from_uniform_bytes(c_raw_arr)
}

/// Sign a name binding authorization
///
/// # Arguments
/// * `ivk` - Incoming viewing key (secret scalar)
/// * `g_d` - Diversified base point (derived from diversifier d)
/// * `pk_d` - Transmission key (should equal [ivk] × g_d)
/// * `name` - User-defined name to bind
/// * `address` - Zcash unified address to bind to
///
/// # Returns
/// Schnorr signature (R, s) authorizing the binding
pub fn sign<R: RngCore>(
    rng: &mut R,
    ivk: &Fr,
    g_d: &Point,
    pk_d: &Point,
    name: &str,
    address: &str,
) -> Signature {
    // Step 1: Generate random nonce r
    let r = Fr::random(rng);

    // Step 2: Compute commitment R = [r] × g_d
    let r_point = *g_d * r;

    // Step 3: Compute binding hash
    let binding_hash = compute_binding_hash(name, address);

    // Step 4: Compute challenge c = Hash(R || pk_d || binding_hash)
    let c = compute_challenge(&r_point, pk_d, &binding_hash);

    // Step 5: Compute response s = r + c × ivk
    let s_scalar = r + (c * ivk);

    Signature { r_point, s_scalar }
}

/// Verify a Schnorr signature
///
/// # Arguments
/// * `g_d` - Diversified base point
/// * `pk_d` - Transmission key
/// * `name` - User-defined name
/// * `address` - Zcash unified address
/// * `signature` - Schnorr signature (R, s)
///
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify(g_d: &Point, pk_d: &Point, name: &str, address: &str, signature: &Signature) -> bool {
    // Step 1: Recompute binding hash
    let binding_hash = compute_binding_hash(name, address);

    // Step 2: Recompute challenge c
    let c = compute_challenge(&signature.r_point, pk_d, &binding_hash);

    // Step 3: Verify equation: [s] × g_d == R + [c] × pk_d
    let lhs = *g_d * signature.s_scalar;
    let rhs = signature.r_point + (*pk_d * c);

    lhs == rhs
}

/// Derive g_d from a diversifier using DiversifyHash (GroupHash)
///
/// In Orchard, this uses the sinsemilla hash with domain "z.cash:Orchard-gd"
pub fn diversify_hash(d: &[u8; 11]) -> Point {
    // This is a simplified hash-to-curve
    // The actual Orchard implementation uses sinsemilla::Commit with domain "z.cash:Orchard-gd"
    // For now, we use a simple hash-and-try approach

    let hash_result = Params::new()
        .hash_length(64)
        .personal(b"z.cash:Orchard")
        .hash(d);
    let hash = hash_result.as_array();

    // Try to map hash to curve point
    // We try different prefixes until we find a valid point
    let mut attempt = [0u8; 32];
    for i in 0..=255u8 {
        attempt.copy_from_slice(&hash[0..32]);
        attempt[0] = attempt[0].wrapping_add(i);

        if let Some(point) = Point::from_bytes(&attempt).into_option() {
            return point;
        }
    }

    // Fallback to generator if no valid point found (shouldn't happen)
    Point::generator()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_signature_roundtrip() {
        let mut rng = thread_rng();

        // Generate test keys
        let ivk = Fr::random(&mut rng);
        let r_test = Fr::random(&mut rng);
        let g_d = Point::generator() * r_test; // Random base point

        // Compute pk_d = [ivk] × g_d
        let pk_d = g_d * ivk;

        // Sign
        let name = "alice";
        let address = "u1testaddress123";
        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, name, address);

        // Verify
        assert!(verify(&g_d, &pk_d, name, address, &sig));
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = thread_rng();

        let ivk = Fr::random(&mut rng);
        let g_d = Point::generator();
        let pk_d = g_d * ivk;

        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, "test", "u1test");

        // Serialize
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64);

        // Deserialize
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

        // Wrong name should fail
        assert!(!verify(&g_d, &pk_d, "bob", "u1test", &sig));
    }

    #[test]
    fn test_wrong_address_fails() {
        let mut rng = thread_rng();

        let ivk = Fr::random(&mut rng);
        let g_d = Point::generator();
        let pk_d = g_d * ivk;

        let sig = sign(&mut rng, &ivk, &g_d, &pk_d, "alice", "u1test");

        // Wrong address should fail
        assert!(!verify(&g_d, &pk_d, "alice", "u1other", &sig));
    }
}
