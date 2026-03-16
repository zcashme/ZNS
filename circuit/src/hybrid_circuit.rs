/// ZNS Hybrid Binding Circuit — Groth16 on BLS12-381.
///
/// Proves: "Given ak (authenticated by external Schnorr signature) and
///          precomputed blind_point, the Orchard CommitIvk derivation
///          produces pk_d for the claimed u-address."
///
/// This circuit eliminates 3 BLAKE2b hashes and 2 scalar multiplications
/// from the full ZnsBindingCircuit, reducing constraints from ~16.4M to ~3.9M.
///
/// Public inputs:
///   - ak: (PallasFq, PallasFq) — spend auth key (Schnorr-authenticated)
///   - blind_point: (PallasFq, PallasFq) — precomputed [rivk] * R_base
///   - g_d: (PallasFq, PallasFq) — diversified base point
///   - pk_d: (PallasFq, PallasFq) — transmission key from u-address
///   - binding_hash: [u8; 32] — BLAKE2b("ZNS:name_binding", name || ua)[..32]
///
/// Private witness:
///   - nk: PallasFq — nullifier key
///
/// Steps:
///   1. hash_point = SinsemillaHashToPoint(CommitIvk-M, I2LEBSP_255(ak.x) || I2LEBSP_255(nk))
///   2. commit_point = hash_point + blind_point
///   3. ivk = commit_point.x
///   4. pk_d_computed = [ivk] * g_d
///   5. Assert pk_d_computed == pk_d
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::fields::PallasFq;
use crate::gadgets::nonnative_point::{FqVar, PallasPointVar};
use crate::gadgets::sinsemilla::{sinsemilla_hash_to_point, SinsemillaTable};

type NativeFr = ark_bls12_381::Fr;

#[derive(Clone)]
pub struct ZnsHybridCircuit {
    // --- Public inputs ---
    /// Spend authorization key, authenticated by external Schnorr signature.
    pub ak: Option<(PallasFq, PallasFq)>,
    /// Precomputed blinding point: [rivk] * R_base.
    pub blind_point: Option<(PallasFq, PallasFq)>,
    /// Diversified base point g_d = DiversifyHash(d).
    pub g_d: Option<(PallasFq, PallasFq)>,
    /// Transmission key pk_d from the signer's u-address.
    pub pk_d: Option<(PallasFq, PallasFq)>,
    /// Binding hash = BLAKE2b-512("ZNS:name_binding", name || ua)[..32].
    pub binding_hash: Option<[u8; 32]>,

    // --- Private witness ---
    /// Nullifier key nk = ToBase(PRF_expand(sk, 0x07)).
    pub nk_witness: Option<PallasFq>,

    // --- Precomputed constants ---
    /// Sinsemilla table for CommitIvk-M domain.
    pub commit_ivk_table: SinsemillaTable,
}

impl ConstraintSynthesizer<NativeFr> for ZnsHybridCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<NativeFr>,
    ) -> Result<(), SynthesisError> {
        // =============================================
        // 1. Allocate public inputs
        // =============================================
        // ak (spend auth key) — public, authenticated by Schnorr
        let ak_var = PallasPointVar::new_input(
            cs.clone(),
            self.ak.map(|(x, _)| x),
            self.ak.map(|(_, y)| y),
        )?;

        // blind_point = [rivk] * R_base — public, precomputed
        let blind_point_var = PallasPointVar::new_input(
            cs.clone(),
            self.blind_point.map(|(x, _)| x),
            self.blind_point.map(|(_, y)| y),
        )?;

        // g_d — public, derived from diversifier
        let g_d_var = PallasPointVar::new_input(
            cs.clone(),
            self.g_d.map(|(x, _)| x),
            self.g_d.map(|(_, y)| y),
        )?;

        // =============================================
        // 2. Allocate private witness: nk
        // =============================================
        let nk = FqVar::new_witness(cs.clone(), || {
            self.nk_witness.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // =============================================
        // 3. SinsemillaHashToPoint
        //    message = I2LEBSP_255(ak.x) || I2LEBSP_255(nk) = 510 bits
        //    510 / 10 = 51 chunks, no padding needed
        // =============================================
        let ak_x_bits = ak_var.x.to_bits_le()?;
        let nk_bits = nk.to_bits_le()?;

        let mut commit_msg_bits = Vec::with_capacity(510);
        commit_msg_bits.extend_from_slice(&ak_x_bits[..255]);
        commit_msg_bits.extend_from_slice(&nk_bits[..255]);

        let hash_point = sinsemilla_hash_to_point(
            cs.clone(),
            &self.commit_ivk_table,
            &commit_msg_bits,
        )?;

        // =============================================
        // 4. commit_point = hash_point + blind_point
        // =============================================
        let commit_point = PallasPointVar::add(cs.clone(), &hash_point, &blind_point_var)?;

        // =============================================
        // 5. ivk = commit_point.x
        //    pk_d_computed = [ivk] * g_d
        // =============================================
        let ivk_bits = commit_point.x.to_bits_le()?;
        let pk_d_computed = PallasPointVar::scalar_mul(cs.clone(), &ivk_bits, &g_d_var)?;

        // =============================================
        // 6. Allocate pk_d as public input, enforce equality
        // =============================================
        let pk_d_var = PallasPointVar::new_input(
            cs.clone(),
            self.pk_d.map(|(x, _)| x),
            self.pk_d.map(|(_, y)| y),
        )?;

        pk_d_computed.enforce_equal(&pk_d_var)?;

        // =============================================
        // 7. Allocate binding_hash as public input (256 bits)
        // =============================================
        let _binding_bits: Vec<Boolean<NativeFr>> = {
            let bh = self.binding_hash;
            (0..256)
                .map(|i| {
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    Boolean::new_input(cs.clone(), || {
                        bh.map(|h| (h[byte_idx] >> bit_idx) & 1 == 1)
                            .ok_or(SynthesisError::AssignmentMissing)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(())
    }
}
