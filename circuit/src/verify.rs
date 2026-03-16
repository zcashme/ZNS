/// ZNS proof verification module.
///
/// Provides self-contained verifiers that take raw bytes and return bool.
/// No arkworks types leak to the caller.

use ark_bls12_381::Bls12_381;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;

use crate::circuit::compute_binding_hash;
use crate::fields::PallasFq;
use crate::schnorr::{self, SchnorrSignature};

type NativeFr = ark_bls12_381::Fr;

// =================================================================
// Original (full circuit) verifier — kept for backward compatibility
// =================================================================

/// Pre-loaded verifier for ZNS binding proofs (original full circuit).
pub struct ZnsVerifier {
    pvk: PreparedVerifyingKey<Bls12_381>,
    g_d_x: [u8; 32],
    g_d_y: [u8; 32],
    pk_d_x: [u8; 32],
    pk_d_y: [u8; 32],
}

impl ZnsVerifier {
    pub fn new(
        vk_bytes: &[u8],
        g_d_x: [u8; 32],
        g_d_y: [u8; 32],
        pk_d_x: [u8; 32],
        pk_d_y: [u8; 32],
    ) -> Option<Self> {
        let vk: VerifyingKey<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(vk_bytes).ok()?;
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).ok()?;
        Some(Self { pvk, g_d_x, g_d_y, pk_d_x, pk_d_y })
    }

    pub fn verify(&self, proof_bytes: &[u8], name: &str, bound_ua: &str) -> bool {
        let proof: Proof<Bls12_381> = match CanonicalDeserialize::deserialize_compressed(
            &proof_bytes[..],
        ) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let binding_hash = compute_binding_hash(name, bound_ua);

        let g_d = (
            PallasFq::from_le_bytes_mod_order(&self.g_d_x),
            PallasFq::from_le_bytes_mod_order(&self.g_d_y),
        );
        let pk_d = (
            PallasFq::from_le_bytes_mod_order(&self.pk_d_x),
            PallasFq::from_le_bytes_mod_order(&self.pk_d_y),
        );

        let public_inputs = build_legacy_public_inputs(g_d, pk_d, &binding_hash);

        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &public_inputs, &proof)
            .unwrap_or(false)
    }
}

fn build_legacy_public_inputs(
    g_d: (PallasFq, PallasFq),
    pk_d: (PallasFq, PallasFq),
    binding_hash: &[u8; 32],
) -> Vec<NativeFr> {
    let cs = ConstraintSystem::<NativeFr>::new_ref();

    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(g_d.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(g_d.1)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(pk_d.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(pk_d.1)).unwrap();

    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (binding_hash[byte_idx] >> bit_idx) & 1 == 1;
        let _ = Boolean::<NativeFr>::new_input(cs.clone(), || Ok(bit)).unwrap();
    }

    let binding = cs.borrow().unwrap();
    binding.instance_assignment[1..].to_vec()
}

// =================================================================
// Hybrid (Schnorr + Groth16) verifier
// =================================================================

/// Verifier for ZNS hybrid binding proofs (Schnorr + reduced Groth16).
pub struct ZnsHybridVerifier {
    pvk: PreparedVerifyingKey<Bls12_381>,
}

impl ZnsHybridVerifier {
    /// Create from a serialized (compressed) verification key.
    pub fn new(vk_bytes: &[u8]) -> Option<Self> {
        let vk: VerifyingKey<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(vk_bytes).ok()?;
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).ok()?;
        Some(Self { pvk })
    }

    /// Verify a hybrid ZNS binding proof.
    ///
    /// - `ak_bytes`: compressed ak point (32 bytes)
    /// - `blind_point_bytes`: compressed blind_point (32 bytes)
    /// - `schnorr_sig_bytes`: Schnorr signature (64 bytes)
    /// - `groth16_proof_bytes`: compressed Groth16 proof
    /// - `g_d`: diversified base point as (x_le, y_le) byte arrays
    /// - `pk_d`: transmission key as (x_le, y_le) byte arrays
    /// - `name`: the name being bound
    /// - `bound_ua`: the unified address string
    pub fn verify(
        &self,
        ak_bytes: &[u8; 32],
        blind_point_bytes: &[u8; 32],
        schnorr_sig_bytes: &[u8; 64],
        groth16_proof_bytes: &[u8],
        g_d_x: &[u8; 32],
        g_d_y: &[u8; 32],
        pk_d_x: &[u8; 32],
        pk_d_y: &[u8; 32],
        name: &str,
        bound_ua: &str,
    ) -> bool {
        // 1. Verify Schnorr signature
        let binding_hash = compute_binding_hash(name, bound_ua);
        let schnorr_msg = schnorr::build_schnorr_message(ak_bytes, blind_point_bytes, &binding_hash);
        let schnorr_sig = SchnorrSignature::from_bytes(schnorr_sig_bytes);

        if !schnorr::schnorr_verify(ak_bytes, &schnorr_msg, &schnorr_sig) {
            return false;
        }

        // 2. Verify Groth16 proof
        let proof: Proof<Bls12_381> = match CanonicalDeserialize::deserialize_compressed(
            groth16_proof_bytes,
        ) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let ak = (
            PallasFq::from_le_bytes_mod_order(g_d_x), // wait this is wrong
            PallasFq::from_le_bytes_mod_order(g_d_y),
        );
        // Fix: use the correct byte arrays
        let ak_fq = pallas_bytes_to_fq_pair(ak_bytes);
        let blind_fq = pallas_bytes_to_fq_pair(blind_point_bytes);
        let g_d = (
            PallasFq::from_le_bytes_mod_order(g_d_x),
            PallasFq::from_le_bytes_mod_order(g_d_y),
        );
        let pk_d = (
            PallasFq::from_le_bytes_mod_order(pk_d_x),
            PallasFq::from_le_bytes_mod_order(pk_d_y),
        );

        let public_inputs = match (ak_fq, blind_fq) {
            (Some(ak), Some(bp)) => {
                build_hybrid_public_inputs(ak, bp, g_d, pk_d, &binding_hash)
            }
            _ => return false,
        };

        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &public_inputs, &proof)
            .unwrap_or(false)
    }
}

/// Decompress a 32-byte Pallas point to (PallasFq, PallasFq) affine coordinates.
fn pallas_bytes_to_fq_pair(compressed: &[u8; 32]) -> Option<(PallasFq, PallasFq)> {
    use group::GroupEncoding;
    use pasta_curves::arithmetic::CurveAffine;
    use pasta_curves::pallas;

    let affine_ct = pallas::Affine::from_bytes(compressed);
    if bool::from(affine_ct.is_none()) {
        return None;
    }
    let affine = affine_ct.unwrap();
    let coords = affine.coordinates().unwrap();
    let x_bytes: [u8; 32] = ff::PrimeField::to_repr(coords.x());
    let y_bytes: [u8; 32] = ff::PrimeField::to_repr(coords.y());
    Some((
        PallasFq::from_le_bytes_mod_order(&x_bytes),
        PallasFq::from_le_bytes_mod_order(&y_bytes),
    ))
}

/// Build Groth16 public inputs for the hybrid circuit.
/// Must match allocation order in ZnsHybridCircuit::generate_constraints.
pub fn build_hybrid_public_inputs(
    ak: (PallasFq, PallasFq),
    blind_point: (PallasFq, PallasFq),
    g_d: (PallasFq, PallasFq),
    pk_d: (PallasFq, PallasFq),
    binding_hash: &[u8; 32],
) -> Vec<NativeFr> {
    let cs = ConstraintSystem::<NativeFr>::new_ref();

    // Order must match ZnsHybridCircuit::generate_constraints exactly:
    // 1. ak (x, y)
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(ak.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(ak.1)).unwrap();

    // 2. blind_point (x, y)
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(blind_point.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(blind_point.1)).unwrap();

    // 3. g_d (x, y)
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(g_d.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(g_d.1)).unwrap();

    // 4. pk_d (x, y)
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(pk_d.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(pk_d.1)).unwrap();

    // 5. binding_hash (256 Boolean bits)
    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (binding_hash[byte_idx] >> bit_idx) & 1 == 1;
        let _ = Boolean::<NativeFr>::new_input(cs.clone(), || Ok(bit)).unwrap();
    }

    let binding = cs.borrow().unwrap();
    binding.instance_assignment[1..].to_vec()
}
