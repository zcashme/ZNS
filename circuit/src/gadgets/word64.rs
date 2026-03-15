/// 64-bit word gadget for BLAKE2b implementation in R1CS.
///
/// Operations: XOR, wrapping addition, rotation (free in R1CS).
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError, Variable};

/// A 64-bit word represented as 64 Boolean constraint variables (little-endian).
#[derive(Clone, Debug)]
pub struct Word64<F: PrimeField> {
    pub bits: Vec<Boolean<F>>,
}

impl<F: PrimeField> Word64<F> {
    /// Create a constant word from a u64 value.
    pub fn constant(val: u64) -> Self {
        let bits = (0..64)
            .map(|i| Boolean::constant((val >> i) & 1 == 1))
            .collect();
        Word64 { bits }
    }

    /// Allocate a word as a private witness.
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        val: Option<u64>,
    ) -> Result<Self, SynthesisError> {
        let bits = (0..64)
            .map(|i| {
                Boolean::new_witness(cs.clone(), || {
                    val.map(|v| (v >> i) & 1 == 1)
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Word64 { bits })
    }

    /// XOR two words (64 constraints).
    pub fn xor(&self, other: &Self) -> Result<Self, SynthesisError> {
        let bits = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .map(|(a, b)| a.xor(b))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Word64 { bits })
    }

    /// Rotate right by `n` positions (free — just reindexes bits).
    pub fn rotr(&self, n: usize) -> Self {
        let n = n % 64;
        let mut new_bits = vec![Boolean::FALSE; 64];
        for i in 0..64 {
            new_bits[i] = self.bits[(i + n) % 64].clone();
        }
        Word64 { bits: new_bits }
    }

    /// Wrapping addition of two 64-bit words.
    ///
    /// Uses a ripple-carry adder: per bit, allocate sum_bit and carry_out,
    /// then constrain `a + b + carry_in = carry_out * 2 + sum_bit`.
    /// Cost: ~128 constraints (2 per bit).
    pub fn wrapping_add(
        cs: ConstraintSystemRef<F>,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError> {
        let a_vals: Vec<Option<bool>> = a.bits.iter().map(|b| b.value().ok()).collect();
        let b_vals: Vec<Option<bool>> = b.bits.iter().map(|b| b.value().ok()).collect();

        // Compute concrete carry and sum values (if available).
        let mut carry_vals = vec![None; 65];
        carry_vals[0] = Some(false);
        for i in 0..64 {
            carry_vals[i + 1] = match (a_vals[i], b_vals[i], carry_vals[i]) {
                (Some(a), Some(b), Some(c)) => {
                    let sum = a as u8 + b as u8 + c as u8;
                    Some(sum >= 2)
                }
                _ => None,
            };
        }

        let mut sum_bits = Vec::with_capacity(64);
        let mut carry = Boolean::<F>::FALSE;

        for i in 0..64 {
            // carry_out = (a + b + carry_in) >= 2
            let carry_out = Boolean::new_witness(cs.clone(), || {
                carry_vals[i + 1].ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Constraint: a[i] + b[i] + carry_in = carry_out * 2 + sum_bit
            // Rearranged: sum_bit = a[i] + b[i] + carry_in - 2 * carry_out
            // We enforce this via a linear constraint.
            let a_lc = a.bits[i].lc();
            let b_lc = b.bits[i].lc();
            let carry_in_lc = carry.lc();
            let carry_out_lc = carry_out.lc();

            // sum = a + b + carry_in - 2*carry_out (must be 0 or 1)
            // We allocate sum_bit and constrain it.
            let sum_val = match (a_vals[i], b_vals[i], carry_vals[i]) {
                (Some(a), Some(b), Some(c)) => {
                    let s = a as u8 + b as u8 + c as u8;
                    Some(s % 2 == 1)
                }
                _ => None,
            };
            let sum_bit =
                Boolean::new_witness(cs.clone(), || {
                    sum_val.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Enforce: a + b + carry_in = 2*carry_out + sum_bit
            cs.enforce_constraint(
                lc!() + Variable::One,
                a_lc.clone() + &b_lc + &carry_in_lc - &carry_out_lc - &carry_out_lc - &sum_bit.lc(),
                lc!(),
            )?;

            sum_bits.push(sum_bit);
            carry = carry_out;
        }
        // Discard final carry (wrapping semantics).

        Ok(Word64 { bits: sum_bits })
    }

    /// Wrapping addition of three words: a + b + c.
    /// Used in BLAKE2b G function: v[a] = v[a] + v[b] + x.
    pub fn wrapping_add3(
        cs: ConstraintSystemRef<F>,
        a: &Self,
        b: &Self,
        c: &Self,
    ) -> Result<Self, SynthesisError> {
        let tmp = Self::wrapping_add(cs.clone(), a, b)?;
        Self::wrapping_add(cs, &tmp, c)
    }

    /// Convert to bytes (little-endian) for use after BLAKE2b.
    pub fn to_bytes_le(&self) -> Vec<Vec<Boolean<F>>> {
        self.bits.chunks(8).map(|chunk| chunk.to_vec()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_wrapping_add() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = Word64::new_witness(cs.clone(), Some(0xFFFFFFFFFFFFFFFF)).unwrap();
        let b = Word64::new_witness(cs.clone(), Some(1)).unwrap();
        let c = Word64::wrapping_add(cs.clone(), &a, &b).unwrap();
        let val: u64 = c
            .bits
            .iter()
            .enumerate()
            .map(|(i, b)| if b.value().unwrap() { 1u64 << i } else { 0 })
            .sum();
        assert_eq!(val, 0); // wraps around
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_xor() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = Word64::new_witness(cs.clone(), Some(0xAA00FF00AA00FF00)).unwrap();
        let b = Word64::new_witness(cs.clone(), Some(0x5500FF005500FF00)).unwrap();
        let c = a.xor(&b).unwrap();
        let val: u64 = c
            .bits
            .iter()
            .enumerate()
            .map(|(i, b)| if b.value().unwrap() { 1u64 << i } else { 0 })
            .sum();
        assert_eq!(val, 0xAA00FF00AA00FF00 ^ 0x5500FF005500FF00);
        assert!(cs.is_satisfied().unwrap());
    }
}
