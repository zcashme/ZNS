/// ZNS Binding Circuit — Groth16 on BLS12-381.
///
/// Proves: "I know an Orchard spending key `sk` that derives to the signer's u-address,
///          and I authorize binding name N to u-address A."
///
/// Private witness:
///   - sk: [u8; 32] — the Orchard spending key
///
/// Public inputs:
///   - g_d: (PallasFq, PallasFq) — diversified base point (verifier computes from diversifier d)
///   - pk_d: (PallasFq, PallasFq) — transmission key from signer's u-address
///   - binding_hash: [u8; 32] — BLAKE2b-512("ZNS_binding", name || bound_u_address)[..32]
///
/// Derivation enforced in-circuit:
///   1. ask = ToScalar(PRF_expand(sk, 0x06))
///   2. ak  = [ask] * SpendAuthBase
///   3. nk  = ToBase(PRF_expand(sk, 0x07))
///   4. rivk = ToScalar(PRF_expand(sk, 0x08))
///   5. ivk = SinsemillaShortCommit("z.cash:Orchard-CommitIvk", ak || nk, rivk)
///   6. pk_d_computed = [ivk] * g_d
///   7. Assert pk_d_computed == pk_d (public input)
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::fields::PallasFq;
use crate::gadgets::blake2b;
use crate::gadgets::nonnative_point::{bits_512_to_fq_mod, PallasPointVar};
use crate::gadgets::sinsemilla::{sinsemilla_short_commit, SinsemillaTable};
use crate::gadgets::word64::Word64;

type NativeFr = ark_bls12_381::Fr;

/// The ZNS binding circuit.
#[derive(Clone)]
pub struct ZnsBindingCircuit {
    /// Spending key (private witness). None during parameter generation.
    pub sk: Option<[u8; 32]>,

    // --- Public inputs (provided by verifier) ---
    /// Diversified base point g_d = DiversifyHash(d), computed externally.
    pub g_d: Option<(PallasFq, PallasFq)>,
    /// Transmission key pk_d from the signer's u-address.
    pub pk_d: Option<(PallasFq, PallasFq)>,
    /// Binding hash = BLAKE2b-512("ZNS:name_binding", name || bound_u_address)[..32].
    pub binding_hash: Option<[u8; 32]>,

    // --- Precomputed constants ---
    /// SpendAuthBase generator.
    pub spend_auth_base: (PallasFq, PallasFq),
    /// Sinsemilla table for CommitIvk.
    pub commit_ivk_table: SinsemillaTable,
    /// Blinding base for CommitIvk.
    pub commit_ivk_r_base: (PallasFq, PallasFq),
}

impl ConstraintSynthesizer<NativeFr> for ZnsBindingCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<NativeFr>,
    ) -> Result<(), SynthesisError> {
        // =============================================
        // 1. Allocate spending key as private witness
        // =============================================
        // Convert sk bytes to 4 Word64 values for BLAKE2b.
        let sk_words: [Word64<NativeFr>; 4] = {
            let sk = self.sk;
            [
                Word64::new_witness(cs.clone(), sk.map(|s| u64::from_le_bytes(s[0..8].try_into().unwrap())))?,
                Word64::new_witness(cs.clone(), sk.map(|s| u64::from_le_bytes(s[8..16].try_into().unwrap())))?,
                Word64::new_witness(cs.clone(), sk.map(|s| u64::from_le_bytes(s[16..24].try_into().unwrap())))?,
                Word64::new_witness(cs.clone(), sk.map(|s| u64::from_le_bytes(s[24..32].try_into().unwrap())))?,
            ]
        };

        // =============================================
        // 2. Derive ask bits via BLAKE2b
        //    For scalar mul, [x]G = [x mod r_P]G on a group of order r_P,
        //    so we use raw BLAKE2b bits directly (512 bits).
        // =============================================
        let prf_ask = blake2b::prf_expand(cs.clone(), &sk_words, 0x06)?;
        let ask_bits = blake2b::hash_to_bits(&prf_ask);
        eprintln!("  after BLAKE2b(ask): {} constraints", cs.num_constraints());

        // =============================================
        // 3. Derive ak = [ask] * SpendAuthBase
        // =============================================
        let spend_auth_base = PallasPointVar::constant(
            cs.clone(),
            self.spend_auth_base.0,
            self.spend_auth_base.1,
        )?;
        let ak_point = PallasPointVar::scalar_mul(cs.clone(), &ask_bits, &spend_auth_base)?;
        eprintln!("  after ak scalar mul: {} constraints", cs.num_constraints());

        // =============================================
        // 4. nk = ToBase(PRF_expand(sk, 0x07))
        //    BLAKE2b produces 512 bits; reduce mod q_P to get nk as a Pallas Fq element.
        // =============================================
        let prf_nk = blake2b::prf_expand(cs.clone(), &sk_words, 0x07)?;
        let nk_bits = blake2b::hash_to_bits(&prf_nk);
        let nk = bits_512_to_fq_mod(cs.clone(), &nk_bits)?;
        eprintln!("  after nk: {} constraints", cs.num_constraints());

        // =============================================
        // 5. Derive rivk bits via BLAKE2b
        //    Used as scalar for blinding in SinsemillaCommit.
        // =============================================
        let prf_rivk = blake2b::prf_expand(cs.clone(), &sk_words, 0x08)?;
        let rivk_bits = blake2b::hash_to_bits(&prf_rivk);
        eprintln!("  after rivk: {} constraints", cs.num_constraints());

        // =============================================
        // 6. Compute ivk = SinsemillaShortCommit(
        //      "z.cash:Orchard-CommitIvk",
        //      I2LEBSP_255(ak_x) || I2LEBSP_255(nk),
        //      rivk
        //    )
        // =============================================
        let ak_x_bits = ak_point.x.to_bits_le()?;
        let nk_bits = nk.to_bits_le()?;

        // Message = I2LEBSP_255(ak_x) || I2LEBSP_255(nk) = 510 bits.
        // Pad to 520 bits (multiple of 10) for Sinsemilla.
        let mut commit_msg_bits = Vec::with_capacity(520);
        commit_msg_bits.extend_from_slice(&ak_x_bits[..255]);
        commit_msg_bits.extend_from_slice(&nk_bits[..255]);
        for _ in 0..10 {
            commit_msg_bits.push(Boolean::constant(false));
        }

        let ivk = sinsemilla_short_commit(
            cs.clone(),
            &self.commit_ivk_table,
            self.commit_ivk_r_base,
            &commit_msg_bits,
            &rivk_bits,
        )?;

        // =============================================
        // 7. Compute pk_d = [ivk] * g_d
        // =============================================
        // Allocate g_d as public input.
        let g_d_var = PallasPointVar::new_input(
            cs.clone(),
            self.g_d.map(|(x, _)| x),
            self.g_d.map(|(_, y)| y),
        )?;

        // ivk is a Fq element, used as a scalar for multiplication.
        // Get its bit decomposition.
        let ivk_bits = ivk.to_bits_le()?;
        let pk_d_computed = PallasPointVar::scalar_mul(cs.clone(), &ivk_bits, &g_d_var)?;

        // =============================================
        // 8. Allocate pk_d as public input and enforce equality
        // =============================================
        let pk_d_var = PallasPointVar::new_input(
            cs.clone(),
            self.pk_d.map(|(x, _)| x),
            self.pk_d.map(|(_, y)| y),
        )?;
        pk_d_computed.enforce_equal(&pk_d_var)?;

        // =============================================
        // 9. Allocate binding_hash as public input
        // =============================================
        // binding_hash is 32 bytes = 256 bits, exposed as public input.
        // It binds the proof to (name, bound_u_address) but has no further constraints.
        let binding_bits: Vec<Boolean<NativeFr>> = {
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
        // No constraints on binding_hash — it's bound via the Groth16 verification equation.
        let _ = binding_bits;

        Ok(())
    }
}

// ============================
// Out-of-circuit helpers
// ============================

/// Compute the binding hash outside the circuit.
/// binding_hash = BLAKE2b-512("ZNS:name_binding", name || bound_u_address)[..32]
pub fn compute_binding_hash(name: &str, bound_u_address: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(name.as_bytes());
    input.extend_from_slice(bound_u_address.as_bytes());

    // Personalization must be exactly 16 bytes.
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ZNS:name_binding")
        .hash(&input);

    let mut out = [0u8; 32];
    out.copy_from_slice(&hash.as_bytes()[..32]);
    out
}
