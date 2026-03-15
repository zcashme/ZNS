/// Sinsemilla hash and commit gadgets for R1CS.
///
/// Sinsemilla is used in Orchard for:
///   - CommitIvk: deriving ivk from (ak, nk) with blinding rivk
///   - DiversifyHash: deriving g_d from diversifier d (moved outside circuit)
///
/// SinsemillaHashToPoint(D, M):
///   Q = HashToPoint("z.cash:SinsemillaQ", D)
///   for each 10-bit chunk m_i of M:
///     Q = [2](Q + S(m_i))
///   return Q
///
/// where S(j) = GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j)) for j in 0..1023.
///
/// SinsemillaCommit_r(D, M):
///   hash_point = SinsemillaHashToPoint(D || "-M", M)
///   R = GroupHash(D || "-r", "")
///   return hash_point + [r] * R
///
/// In R1CS (without lookup tables), we implement the 10-bit chunk selection
/// via a binary tree of conditional selects.
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::fields::PallasFq;
use super::nonnative_point::{FqVar, PallasPointVar};

type NativeFr = ark_bls12_381::Fr;

/// Precomputed Sinsemilla S-table entry: (x, y) affine coordinates on Pallas.
/// S(j) = GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j)) for j in 0..1024.
///
/// These must be computed at initialization using the pasta_curves crate.
#[derive(Clone)]
pub struct SinsemillaTable {
    /// 1024 entries, each a (PallasFq, PallasFq) affine point.
    pub entries: Vec<(PallasFq, PallasFq)>,
    /// Q point for the specific domain.
    pub q: (PallasFq, PallasFq),
}

impl SinsemillaTable {
    /// Select S(chunk_value) from the table using a binary tree of conditional selects.
    ///
    /// chunk_bits: 10 Boolean bits (little-endian) representing the chunk value 0..1023.
    /// Returns the selected point as a PallasPointVar.
    ///
    /// Cost: ~1023 conditional selects × 2 non-native field muxes ≈ ~20,000 constraints per chunk.
    fn select_s(
        &self,
        cs: ConstraintSystemRef<NativeFr>,
        chunk_bits: &[Boolean<NativeFr>],
    ) -> Result<PallasPointVar, SynthesisError> {
        assert_eq!(chunk_bits.len(), 10);
        assert_eq!(self.entries.len(), 1024);

        // Start with all 1024 candidates as constant FqVar pairs.
        let mut candidates: Vec<(FqVar, FqVar)> = self
            .entries
            .iter()
            .map(|(x, y)| {
                Ok((
                    FqVar::new_constant(cs.clone(), *x)?,
                    FqVar::new_constant(cs.clone(), *y)?,
                ))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // Binary tree selection: 10 levels, each halves the candidates.
        for bit in chunk_bits {
            let mut next = Vec::with_capacity(candidates.len() / 2);
            for pair in candidates.chunks(2) {
                let x = FqVar::conditionally_select(bit, &pair[1].0, &pair[0].0)?;
                let y = FqVar::conditionally_select(bit, &pair[1].1, &pair[0].1)?;
                next.push((x, y));
            }
            candidates = next;
        }

        assert_eq!(candidates.len(), 1);
        let (x, y) = candidates.into_iter().next().unwrap();

        Ok(PallasPointVar {
            x,
            y,
            is_infinity: Boolean::constant(false),
        })
    }
}

/// SinsemillaHashToPoint(D, M) in R1CS.
///
/// table: precomputed S-table and Q for domain D.
/// message_bits: the message M as Boolean bits (must be a multiple of 10).
///
/// Returns the hash as a PallasPointVar.
pub fn sinsemilla_hash_to_point(
    cs: ConstraintSystemRef<NativeFr>,
    table: &SinsemillaTable,
    message_bits: &[Boolean<NativeFr>],
) -> Result<PallasPointVar, SynthesisError> {
    assert!(
        message_bits.len() % 10 == 0,
        "Sinsemilla message must be a multiple of 10 bits, got {}",
        message_bits.len()
    );

    let (qx, qy) = table.q;
    let mut acc = PallasPointVar::constant(cs.clone(), qx, qy)?;

    for (i, chunk) in message_bits.chunks(10).enumerate() {
        // Look up S(chunk_value).
        let s_point = table.select_s(
            cs.clone(),
            chunk,
        )?;

        // acc = [2](acc + S(chunk_value))
        let sum = PallasPointVar::add(cs.clone(), &acc, &s_point)?;
        acc = PallasPointVar::double(cs.clone(), &sum)?;
    }

    Ok(acc)
}

/// SinsemillaCommit_r(D, M) = SinsemillaHashToPoint(D-M, M) + [r] * R
///
/// table: S-table and Q for domain D-M (i.e., "z.cash:Orchard-CommitIvk-M").
/// r_base: the blinding base R = GroupHash(D-r, ""), precomputed as (x, y).
/// message_bits: M as Boolean bits.
/// r_bits: the blinding scalar r (rivk) as Boolean bits (little-endian).
///
/// Returns the commitment point.
pub fn sinsemilla_commit(
    cs: ConstraintSystemRef<NativeFr>,
    table: &SinsemillaTable,
    r_base: (PallasFq, PallasFq),
    message_bits: &[Boolean<NativeFr>],
    r_bits: &[Boolean<NativeFr>],
) -> Result<PallasPointVar, SynthesisError> {
    // hash_point = SinsemillaHashToPoint(D-M, M)
    let hash_point = sinsemilla_hash_to_point(cs.clone(), table, message_bits)?;

    // R = constant base point for blinding
    let r_point = PallasPointVar::constant(cs.clone(), r_base.0, r_base.1)?;

    // blind_point = [r] * R
    let blind_point = PallasPointVar::scalar_mul(cs.clone(), r_bits, &r_point)?;

    // result = hash_point + blind_point
    PallasPointVar::add(cs, &hash_point, &blind_point)
}

/// SinsemillaShortCommit: extract x-coordinate of SinsemillaCommit result.
/// This is what produces ivk.
pub fn sinsemilla_short_commit(
    cs: ConstraintSystemRef<NativeFr>,
    table: &SinsemillaTable,
    r_base: (PallasFq, PallasFq),
    message_bits: &[Boolean<NativeFr>],
    r_bits: &[Boolean<NativeFr>],
) -> Result<FqVar, SynthesisError> {
    let commit_point = sinsemilla_commit(cs, table, r_base, message_bits, r_bits)?;
    Ok(commit_point.x)
}
