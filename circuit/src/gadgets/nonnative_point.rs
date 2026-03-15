/// Non-native Pallas curve point arithmetic inside BLS12-381 R1CS.
///
/// Pallas curve: y² = x³ + 5 over Fq
/// All field operations are emulated via NonNativeFieldVar<PallasFq, BLS12Fr>.
///
/// Operations: addition, doubling, scalar multiplication, compression.
use ark_ff::{Field, One, Zero};
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::fields::PallasFq;

/// BLS12-381 scalar field (the "native" field of our R1CS).
type NativeFr = ark_bls12_381::Fr;

/// Non-native Pallas base field variable.
pub type FqVar = NonNativeFieldVar<PallasFq, NativeFr>;

/// A point on the Pallas curve, represented as (x, y) in affine coordinates.
/// Uses non-native field variables for both coordinates.
#[derive(Clone, Debug)]
pub struct PallasPointVar {
    pub x: FqVar,
    pub y: FqVar,
    /// Whether this is the point at infinity (for edge-case handling in scalar mul).
    pub is_infinity: Boolean<NativeFr>,
}

impl PallasPointVar {
    /// Allocate a point as a private witness.
    pub fn new_witness(
        cs: ConstraintSystemRef<NativeFr>,
        x_val: Option<PallasFq>,
        y_val: Option<PallasFq>,
    ) -> Result<Self, SynthesisError> {
        let x = FqVar::new_witness(cs.clone(), || {
            x_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FqVar::new_witness(cs.clone(), || {
            y_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let is_infinity = Boolean::new_witness(cs, || Ok(false))?;
        Ok(PallasPointVar { x, y, is_infinity })
    }

    /// Allocate a point as a public input.
    pub fn new_input(
        cs: ConstraintSystemRef<NativeFr>,
        x_val: Option<PallasFq>,
        y_val: Option<PallasFq>,
    ) -> Result<Self, SynthesisError> {
        let x = FqVar::new_input(cs.clone(), || {
            x_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FqVar::new_input(cs.clone(), || {
            y_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let is_infinity = Boolean::constant(false);
        Ok(PallasPointVar { x, y, is_infinity })
    }

    /// Create a constant point (e.g., a generator or precomputed value).
    pub fn constant(
        cs: ConstraintSystemRef<NativeFr>,
        x_val: PallasFq,
        y_val: PallasFq,
    ) -> Result<Self, SynthesisError> {
        let x = FqVar::new_constant(cs.clone(), x_val)?;
        let y = FqVar::new_constant(cs, y_val)?;
        Ok(PallasPointVar {
            x,
            y,
            is_infinity: Boolean::constant(false),
        })
    }

    /// Point addition: P + Q (assuming P ≠ Q, P ≠ -Q, neither is infinity).
    ///
    /// lambda = (y2 - y1) / (x2 - x1)
    /// x3 = lambda² - x1 - x2
    /// y3 = lambda * (x1 - x3) - y1
    ///
    /// We avoid division by allocating lambda as a witness and constraining:
    ///   (x2 - x1) * lambda = y2 - y1
    ///   lambda * lambda = x3 + x1 + x2
    ///   lambda * (x1 - x3) = y3 + y1
    pub fn add(
        cs: ConstraintSystemRef<NativeFr>,
        p: &Self,
        q: &Self,
    ) -> Result<Self, SynthesisError> {
        // Compute lambda witness value.
        let lambda_val = {
            let px = p.x.value().ok();
            let py = p.y.value().ok();
            let qx = q.x.value().ok();
            let qy = q.y.value().ok();
            match (px, py, qx, qy) {
                (Some(px), Some(py), Some(qx), Some(qy)) => {
                    let dx = qx - px;
                    if dx.is_zero() {
                        None
                    } else {
                        Some((qy - py) * dx.inverse().unwrap())
                    }
                }
                _ => None,
            }
        };

        let lambda = FqVar::new_witness(cs.clone(), || {
            lambda_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Compute x3, y3 witness values.
        let x3_val = lambda_val.and_then(|l| {
            let px = p.x.value().ok()?;
            let qx = q.x.value().ok()?;
            Some(l * l - px - qx)
        });
        let y3_val = lambda_val.and_then(|l| {
            let px = p.x.value().ok()?;
            let py = p.y.value().ok()?;
            Some(l * (px - x3_val?) - py)
        });

        let x3 = FqVar::new_witness(cs.clone(), || {
            x3_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y3 = FqVar::new_witness(cs.clone(), || {
            y3_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: (x2 - x1) * lambda = y2 - y1
        let dx = &q.x - &p.x;
        let dy = &q.y - &p.y;
        dx.mul_equals(&lambda, &dy)?;

        // Constraint 2: lambda * lambda = x3 + x1 + x2
        let x_sum = &x3 + &p.x + &q.x;
        lambda.mul_equals(&lambda, &x_sum)?;

        // Constraint 3: lambda * (x1 - x3) = y3 + y1
        let dx3 = &p.x - &x3;
        let y_sum = &y3 + &p.y;
        lambda.mul_equals(&dx3, &y_sum)?;

        Ok(PallasPointVar {
            x: x3,
            y: y3,
            is_infinity: Boolean::constant(false),
        })
    }

    /// Point doubling: 2P.
    ///
    /// lambda = (3 * x1² + a) / (2 * y1)   [a = 0 for Pallas]
    /// x3 = lambda² - 2 * x1
    /// y3 = lambda * (x1 - x3) - y1
    pub fn double(
        cs: ConstraintSystemRef<NativeFr>,
        p: &Self,
    ) -> Result<Self, SynthesisError> {
        let lambda_val = {
            let px = p.x.value().ok();
            let py = p.y.value().ok();
            match (px, py) {
                (Some(px), Some(py)) => {
                    let num = px * px * PallasFq::from(3u64); // 3x² (a=0)
                    let den = py + py; // 2y
                    if den.is_zero() {
                        None
                    } else {
                        Some(num * den.inverse().unwrap())
                    }
                }
                _ => None,
            }
        };

        let lambda = FqVar::new_witness(cs.clone(), || {
            lambda_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let x3_val = lambda_val.and_then(|l| {
            let px = p.x.value().ok()?;
            Some(l * l - px - px)
        });
        let y3_val = lambda_val.and_then(|l| {
            let px = p.x.value().ok()?;
            let py = p.y.value().ok()?;
            Some(l * (px - x3_val?) - py)
        });

        let x3 = FqVar::new_witness(cs.clone(), || {
            x3_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y3 = FqVar::new_witness(cs.clone(), || {
            y3_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: 2*y1 * lambda = 3 * x1²  (a=0)
        let two_y = &p.y + &p.y;
        let three = FqVar::new_constant(cs.clone(), PallasFq::from(3u64))?;
        let x_sq = p.x.clone() * &p.x;
        let three_x_sq = &three * &x_sq;
        two_y.mul_equals(&lambda, &three_x_sq)?;

        // Constraint 2: lambda² = x3 + 2*x1
        let two_x = &p.x + &p.x;
        let x_sum = &x3 + &two_x;
        lambda.mul_equals(&lambda, &x_sum)?;

        // Constraint 3: lambda * (x1 - x3) = y3 + y1
        let dx = &p.x - &x3;
        let y_sum = &y3 + &p.y;
        lambda.mul_equals(&dx, &y_sum)?;

        Ok(PallasPointVar {
            x: x3,
            y: y3,
            is_infinity: Boolean::constant(false),
        })
    }

    /// Scalar multiplication: [scalar] * P using double-and-add.
    ///
    /// scalar_bits: little-endian boolean decomposition of the scalar.
    /// base: the point to multiply.
    ///
    /// Uses a simple double-and-add with conditional selection.
    /// For a 255-bit scalar: ~255 doublings + ~128 additions on average.
    pub fn scalar_mul(
        cs: ConstraintSystemRef<NativeFr>,
        scalar_bits: &[Boolean<NativeFr>],
        base: &Self,
    ) -> Result<Self, SynthesisError> {
        // Start from the most significant bit, accumulate via double-and-add.
        // acc = identity (point at infinity)
        // for each bit from MSB to LSB:
        //   acc = 2 * acc
        //   if bit == 1: acc = acc + base
        //
        // To avoid the point-at-infinity edge case at the start, we use a trick:
        // Initialize acc = base (for the MSB which is assumed 1), then process remaining bits.
        // For the general case, we handle it with conditional selection.

        let n = scalar_bits.len();
        if n == 0 {
            // Return the identity — just use (0, 0) as a placeholder.
            let zero = FqVar::new_constant(cs.clone(), PallasFq::zero())?;
            return Ok(PallasPointVar {
                x: zero.clone(),
                y: zero,
                is_infinity: Boolean::constant(true),
            });
        }

        // Double-and-add from MSB to LSB.
        //
        // We start with acc = base (representing the MSB being 1).
        // Process bits n-2 down to 0: double acc, conditionally add base.
        // After the loop, acc = [1 * 2^(n-1) + lower_bits] * base.
        //
        // If the MSB was actually 0, we need to subtract [2^(n-1)] * base.
        // We compute neg_offset = -[2^(n-1)] * base by tracking the offset
        // point through the same doublings.

        let mut acc = base.clone();
        let mut offset = base.clone(); // tracks [2^k] * base for offset correction

        for i in (0..n - 1).rev() {
            acc = Self::double(cs.clone(), &acc)?;
            offset = Self::double(cs.clone(), &offset)?;

            let acc_plus_base = Self::add(cs.clone(), &acc, base)?;
            acc = Self::select(&scalar_bits[i], &acc_plus_base, &acc)?;
        }

        // If MSB (bit n-1) was 0, subtract the offset [2^(n-1)] * base.
        let neg_offset_y = offset.y.negate()?;
        let neg_offset = PallasPointVar {
            x: offset.x.clone(),
            y: neg_offset_y,
            is_infinity: Boolean::constant(false),
        };
        let acc_corrected = Self::add(cs, &acc, &neg_offset)?;

        // result = MSB ? acc : acc_corrected
        Self::select(&scalar_bits[n - 1], &acc, &acc_corrected)
    }

    /// Conditional selection: if condition then a else b.
    pub fn select(
        condition: &Boolean<NativeFr>,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError> {
        let x = FqVar::conditionally_select(condition, &a.x, &b.x)?;
        let y = FqVar::conditionally_select(condition, &a.y, &b.y)?;
        let is_infinity =
            Boolean::conditionally_select(condition, &a.is_infinity, &b.is_infinity)?;
        Ok(PallasPointVar { x, y, is_infinity })
    }

    /// Extract the x-coordinate.
    pub fn x(&self) -> &FqVar {
        &self.x
    }

    /// Enforce that two points are equal.
    pub fn enforce_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        self.x.enforce_equal(&other.x)?;
        self.y.enforce_equal(&other.y)?;
        Ok(())
    }

    /// Compress a point to 32 bytes: x-coordinate LE with sign bit in MSB of last byte.
    /// Returns 256 Boolean bits representing the compressed form.
    pub fn compress(
        &self,
        cs: ConstraintSystemRef<NativeFr>,
    ) -> Result<Vec<Boolean<NativeFr>>, SynthesisError> {
        // Get x-coordinate bits (255 bits for a 255-bit field).
        let x_bits = self.x.to_bits_le()?;

        // Get the sign of y: the least significant bit of the y-coordinate.
        let y_bits = self.y.to_bits_le()?;
        let y_sign = y_bits[0].clone();

        // Compressed form: 256 bits = first 255 bits of x, then y_sign as the 256th bit.
        let mut compressed = Vec::with_capacity(256);
        // Take the first 255 bits of x.
        let x_len = x_bits.len().min(255);
        compressed.extend_from_slice(&x_bits[..x_len]);
        // Pad to 255 if needed.
        while compressed.len() < 255 {
            compressed.push(Boolean::constant(false));
        }
        // Bit 255 (MSB of byte 31) = y_sign.
        compressed.push(y_sign);

        Ok(compressed)
    }
}

/// Convert Boolean bits (LE) to a PallasFq non-native field variable.
///
/// Uses 128-bit chunks to avoid overflow: each 128-bit value is always < q_P (~2^255),
/// so to_bits_le() won't wrap. Chunks are combined via constant multiplications.
pub fn bits_to_fq_var(
    cs: ConstraintSystemRef<NativeFr>,
    bits: &[Boolean<NativeFr>],
) -> Result<FqVar, SynthesisError> {
    const CHUNK: usize = 128;

    // Compute the full value.
    let full_val: Option<PallasFq> = {
        let bit_vals: Option<Vec<bool>> = bits.iter().map(|b| b.value().ok()).collect();
        bit_vals.map(|bv| {
            let mut result = PallasFq::zero();
            let mut power = PallasFq::one();
            let two = PallasFq::from(2u64);
            for b in &bv {
                if *b {
                    result += power;
                }
                power *= two;
            }
            result
        })
    };

    // Process in 128-bit chunks.
    let mut result = FqVar::new_constant(cs.clone(), PallasFq::zero())?;
    let mut shift_val = PallasFq::one(); // 2^(chunk_index * 128)

    for chunk_start in (0..bits.len()).step_by(CHUNK) {
        let chunk_end = (chunk_start + CHUNK).min(bits.len());
        let chunk_bits = &bits[chunk_start..chunk_end];
        let chunk_len = chunk_bits.len();

        // Compute this chunk's value (always < 2^128 < q_P, no wrapping).
        let chunk_val: Option<PallasFq> = {
            let bv: Option<Vec<bool>> = chunk_bits.iter().map(|b| b.value().ok()).collect();
            bv.map(|bv| {
                let mut v = PallasFq::zero();
                let mut p = PallasFq::one();
                let two = PallasFq::from(2u64);
                for b in &bv {
                    if *b {
                        v += p;
                    }
                    p *= two;
                }
                v
            })
        };

        // Allocate chunk as witness.
        let chunk_var = FqVar::new_witness(cs.clone(), || {
            chunk_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constrain: chunk_var's bits match the input chunk bits.
        let chunk_var_bits = chunk_var.to_bits_le()?;
        for (i, input_bit) in chunk_bits.iter().enumerate() {
            if i < chunk_var_bits.len() {
                input_bit.enforce_equal(&chunk_var_bits[i])?;
            }
        }
        // High bits must be zero (proves chunk < 2^chunk_len).
        for extra_bit in chunk_var_bits.iter().skip(chunk_len) {
            extra_bit.enforce_equal(&Boolean::constant(false))?;
        }

        // Accumulate: result += chunk_var * 2^(chunk_index * 128)
        let shift_const = FqVar::new_constant(cs.clone(), shift_val)?;
        result += &(&chunk_var * &shift_const);

        // Advance shift for next chunk.
        let two = PallasFq::from(2u64);
        for _ in 0..chunk_len {
            shift_val *= two;
        }
    }

    Ok(result)
}

/// Convert 512 Boolean bits to a PallasFq element via mod reduction.
/// Used for ToBase^Orchard: leos2ip_512(x) mod q_P.
///
/// This is the full 512-bit to Fq reduction used for nk derivation.
pub fn bits_512_to_fq_mod(
    cs: ConstraintSystemRef<NativeFr>,
    bits: &[Boolean<NativeFr>],
) -> Result<FqVar, SynthesisError> {
    assert!(bits.len() == 512);

    // Compute the value.
    let val: Option<PallasFq> = {
        let bit_vals: Option<Vec<bool>> = bits.iter().map(|b| b.value().ok()).collect();
        bit_vals.map(|bv| {
            // Interpret as 512-bit LE integer, reduce mod q.
            // We compute this via two 256-bit halves.
            let mut lo = PallasFq::zero();
            let mut hi = PallasFq::zero();
            let two = PallasFq::from(2u64);
            let mut power = PallasFq::one();
            for b in &bv[..256] {
                if *b {
                    lo += power;
                }
                power *= two;
            }
            power = PallasFq::one();
            for b in &bv[256..] {
                if *b {
                    hi += power;
                }
                power *= two;
            }
            // result = lo + hi * 2^256 (mod q)
            let two_256 = {
                let mut t = PallasFq::one();
                for _ in 0..256 {
                    t += t;
                }
                t
            };
            lo + hi * two_256
        })
    };

    let result = FqVar::new_witness(cs.clone(), || {
        val.ok_or(SynthesisError::AssignmentMissing)
    })?;

    // Build constraint: result = sum(bits[i] * 2^i) mod q
    // We split into lo (bits 0..255) and hi (bits 256..511),
    // then constrain result = lo + hi * 2^256 (the mod q is implicit in field arithmetic).
    let lo = bits_to_fq_var(cs.clone(), &bits[..256])?;
    let hi = bits_to_fq_var(cs.clone(), &bits[256..])?;

    let two_256 = {
        let mut t = PallasFq::one();
        for _ in 0..256 {
            t += t;
        }
        t
    };
    let two_256_var = FqVar::new_constant(cs, two_256)?;
    let expected = &lo + &(&hi * &two_256_var);
    result.enforce_equal(&expected)?;

    Ok(result)
}

/// Convert Boolean bits (LE) to a PallasFr non-native field variable.
/// Same 128-bit chunk strategy as bits_to_fq_var.
pub fn bits_to_fr_var(
    cs: ConstraintSystemRef<NativeFr>,
    bits: &[Boolean<NativeFr>],
) -> Result<NonNativeFieldVar<crate::fields::PallasFr, NativeFr>, SynthesisError> {
    use crate::fields::PallasFr;
    type FrNNVar = NonNativeFieldVar<PallasFr, NativeFr>;

    const CHUNK: usize = 128;

    let full_val: Option<PallasFr> = {
        let bit_vals: Option<Vec<bool>> = bits.iter().map(|b| b.value().ok()).collect();
        bit_vals.map(|bv| {
            let mut result = PallasFr::zero();
            let mut power = PallasFr::one();
            let two = PallasFr::from(2u64);
            for b in &bv {
                if *b {
                    result += power;
                }
                power *= two;
            }
            result
        })
    };

    let mut result = FrNNVar::new_constant(cs.clone(), PallasFr::zero())?;
    let mut shift_val = PallasFr::one();

    for chunk_start in (0..bits.len()).step_by(CHUNK) {
        let chunk_end = (chunk_start + CHUNK).min(bits.len());
        let chunk_bits = &bits[chunk_start..chunk_end];
        let chunk_len = chunk_bits.len();

        let chunk_val: Option<PallasFr> = {
            let bv: Option<Vec<bool>> = chunk_bits.iter().map(|b| b.value().ok()).collect();
            bv.map(|bv| {
                let mut v = PallasFr::zero();
                let mut p = PallasFr::one();
                let two = PallasFr::from(2u64);
                for b in &bv {
                    if *b {
                        v += p;
                    }
                    p *= two;
                }
                v
            })
        };

        let chunk_var = FrNNVar::new_witness(cs.clone(), || {
            chunk_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let chunk_var_bits = chunk_var.to_bits_le()?;
        for (i, input_bit) in chunk_bits.iter().enumerate() {
            if i < chunk_var_bits.len() {
                input_bit.enforce_equal(&chunk_var_bits[i])?;
            }
        }
        for extra_bit in chunk_var_bits.iter().skip(chunk_len) {
            extra_bit.enforce_equal(&Boolean::constant(false))?;
        }

        let shift_const = FrNNVar::new_constant(cs.clone(), shift_val)?;
        result += &(&chunk_var * &shift_const);

        let two = PallasFr::from(2u64);
        for _ in 0..chunk_len {
            shift_val *= two;
        }
    }

    Ok(result)
}

/// Same as bits_512_to_fq_mod but reduces mod r_P (the scalar field order).
/// Used for ToScalar^Orchard: leos2ip_512(x) mod r_P.
///
/// Returns a PallasFq variable (we represent scalars as Fq for simplicity,
/// since q ≈ r and the circuit treats both as non-native).
/// The caller must ensure the reduction is correct.
pub fn bits_512_to_fr_mod(
    cs: ConstraintSystemRef<NativeFr>,
    bits: &[Boolean<NativeFr>],
) -> Result<NonNativeFieldVar<crate::fields::PallasFr, NativeFr>, SynthesisError> {
    use crate::fields::PallasFr;
    assert!(bits.len() == 512);

    let val: Option<PallasFr> = {
        let bit_vals: Option<Vec<bool>> = bits.iter().map(|b| b.value().ok()).collect();
        bit_vals.map(|bv| {
            let two = PallasFr::from(2u64);
            let mut lo = PallasFr::zero();
            let mut power = PallasFr::one();
            for b in &bv[..256] {
                if *b {
                    lo += power;
                }
                power *= two;
            }
            let mut hi = PallasFr::zero();
            power = PallasFr::one();
            for b in &bv[256..] {
                if *b {
                    hi += power;
                }
                power *= two;
            }
            let two_256 = {
                let mut t = PallasFr::one();
                for _ in 0..256 {
                    t += t;
                }
                t
            };
            lo + hi * two_256
        })
    };

    type FrVar = NonNativeFieldVar<PallasFr, NativeFr>;

    let result = FrVar::new_witness(cs.clone(), || {
        val.ok_or(SynthesisError::AssignmentMissing)
    })?;

    // Constrain: decompose result back to bits, match against input bits.
    // The 512-bit value mod r_P fits in ~255 bits.
    // But the original 512 bits represent a LARGER integer that reduces mod r_P.
    // We split into lo (0..256) and hi (256..512), then constrain:
    //   result = lo_val + hi_val * 2^256  (mod r_P, implicit in field arithmetic)
    // where lo_val and hi_val are constructed from their respective bits.
    let lo_val = bits_to_fr_var(cs.clone(), &bits[..256])?;
    let hi_val = bits_to_fr_var(cs.clone(), &bits[256..])?;

    let two_256 = {
        let mut t = PallasFr::one();
        for _ in 0..256 {
            t += t;
        }
        t
    };
    let two_256_var = FrVar::new_constant(cs, two_256)?;
    let expected = &lo_val + &(&hi_val * &two_256_var);
    result.enforce_equal(&expected)?;

    Ok(result)
}
