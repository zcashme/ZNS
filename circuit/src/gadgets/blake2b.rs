/// BLAKE2b-512 gadget for R1CS, specialized for Orchard's PRF^expand.
///
/// PRF^expand_sk(t) = BLAKE2b-512(personalization="Zcash_ExpandSeed", msg = sk || t)
///
/// No BLAKE2b key parameter — sk is concatenated with the domain byte as the message.
/// Message = sk (32 bytes) || t (1 byte) = 33 bytes, fits in a single 128-byte block.
///
/// Cost: ~100,000 constraints per call (1 compression × 12 rounds × 8 G-functions).
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::word64::Word64;

/// BLAKE2b-512 initialization vector.
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// BLAKE2b message schedule (sigma) — 12 rounds of 16-word permutations.
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b G mixing function.
///
/// v[a] = v[a] + v[b] + x
/// v[d] = (v[d] ^ v[a]) >>> R1
/// v[c] = v[c] + v[d]
/// v[b] = (v[b] ^ v[c]) >>> R2
/// (repeated with y and R3, R4)
fn g<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    v: &mut [Word64<F>; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: &Word64<F>,
    y: &Word64<F>,
) -> Result<(), SynthesisError> {
    // v[a] = v[a] + v[b] + x
    v[a] = Word64::wrapping_add3(cs.clone(), &v[a], &v[b], x)?;
    // v[d] = (v[d] ^ v[a]) >>> 32
    v[d] = v[d].xor(&v[a])?.rotr(32);
    // v[c] = v[c] + v[d]
    v[c] = Word64::wrapping_add(cs.clone(), &v[c], &v[d])?;
    // v[b] = (v[b] ^ v[c]) >>> 24
    v[b] = v[b].xor(&v[c])?.rotr(24);
    // v[a] = v[a] + v[b] + y
    v[a] = Word64::wrapping_add3(cs.clone(), &v[a], &v[b], y)?;
    // v[d] = (v[d] ^ v[a]) >>> 16
    v[d] = v[d].xor(&v[a])?.rotr(16);
    // v[c] = v[c] + v[d]
    v[c] = Word64::wrapping_add(cs.clone(), &v[c], &v[d])?;
    // v[b] = (v[b] ^ v[c]) >>> 63
    v[b] = v[b].xor(&v[c])?.rotr(63);
    Ok(())
}

/// BLAKE2b compression function.
///
/// h: current state (8 words, modified in-place)
/// m: message block (16 words)
/// t: counter (bytes compressed so far)
/// f: true if this is the final block
fn compress<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    h: &mut [Word64<F>; 8],
    m: &[Word64<F>; 16],
    t: u128,
    f: bool,
) -> Result<(), SynthesisError> {
    // Initialize working vector v.
    let mut v: [Word64<F>; 16] = [
        h[0].clone(),
        h[1].clone(),
        h[2].clone(),
        h[3].clone(),
        h[4].clone(),
        h[5].clone(),
        h[6].clone(),
        h[7].clone(),
        Word64::constant(IV[0]),
        Word64::constant(IV[1]),
        Word64::constant(IV[2]),
        Word64::constant(IV[3]),
        // v[12] = IV[4] ^ t_lo
        Word64::constant(IV[4] ^ (t as u64)),
        // v[13] = IV[5] ^ t_hi
        Word64::constant(IV[5] ^ ((t >> 64) as u64)),
        // v[14] = IV[6] ^ (if final: 0xFFFFFFFFFFFFFFFF else 0)
        Word64::constant(IV[6] ^ if f { 0xFFFFFFFFFFFFFFFF } else { 0 }),
        // v[15] = IV[7] (no salt in our use)
        Word64::constant(IV[7]),
    ];

    // 12 rounds.
    for round in 0..12 {
        let s = &SIGMA[round];
        // Column step.
        g(cs.clone(), &mut v, 0, 4, 8, 12, &m[s[0]], &m[s[1]])?;
        g(cs.clone(), &mut v, 1, 5, 9, 13, &m[s[2]], &m[s[3]])?;
        g(cs.clone(), &mut v, 2, 6, 10, 14, &m[s[4]], &m[s[5]])?;
        g(cs.clone(), &mut v, 3, 7, 11, 15, &m[s[6]], &m[s[7]])?;
        // Diagonal step.
        g(cs.clone(), &mut v, 0, 5, 10, 15, &m[s[8]], &m[s[9]])?;
        g(cs.clone(), &mut v, 1, 6, 11, 12, &m[s[10]], &m[s[11]])?;
        g(cs.clone(), &mut v, 2, 7, 8, 13, &m[s[12]], &m[s[13]])?;
        g(cs.clone(), &mut v, 3, 4, 9, 14, &m[s[14]], &m[s[15]])?;
    }

    // Finalize: h[i] = h[i] ^ v[i] ^ v[i+8].
    for i in 0..8 {
        h[i] = h[i].xor(&v[i])?.xor(&v[i + 8])?;
    }

    Ok(())
}

/// Compute the initial BLAKE2b state for PRF^expand (constant, free in R1CS).
///
/// Personalization: "Zcash_ExpandSeed" (16 bytes)
/// No BLAKE2b key — sk is part of the message.
/// Hash length: 64, Fanout: 1, Depth: 1
fn prf_expand_init_state<F: PrimeField>() -> [Word64<F>; 8] {
    let personal_lo = u64::from_le_bytes(*b"Zcash_Ex");
    let personal_hi = u64::from_le_bytes(*b"pandSeed");
    // Parameter block (LE): digest_length=64, key_length=0, fanout=1, depth=1
    let p0: u64 = 0x0101_0000 | 64;

    [
        Word64::constant(IV[0] ^ p0),
        Word64::constant(IV[1]),
        Word64::constant(IV[2]),
        Word64::constant(IV[3]),
        Word64::constant(IV[4]),
        Word64::constant(IV[5]),
        Word64::constant(IV[6] ^ personal_lo),
        Word64::constant(IV[7] ^ personal_hi),
    ]
}

/// PRF^expand_sk(domain_byte) = BLAKE2b-512("Zcash_ExpandSeed", msg = sk || domain_byte)
///
/// The spending key is concatenated with the domain byte as the message.
/// No BLAKE2b key parameter is used.
///
/// Message = sk (32 bytes) || domain_byte (1 byte) = 33 bytes.
/// Fits in a single 128-byte block.
///
/// sk_words: the spending key as 4 Word64 values (32 bytes, little-endian).
/// domain_byte: 0x06 (ask), 0x07 (nk), or 0x08 (rivk).
pub fn prf_expand<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    sk_words: &[Word64<F>; 4],
    domain_byte: u8,
) -> Result<[Word64<F>; 8], SynthesisError> {
    let mut h = prf_expand_init_state::<F>();

    // Single block: sk (32 bytes) || domain_byte (1 byte) || zeros (95 bytes)
    // = 128 bytes total. This is the final (and only) block.
    let block: [Word64<F>; 16] = [
        sk_words[0].clone(),
        sk_words[1].clone(),
        sk_words[2].clone(),
        sk_words[3].clone(),
        Word64::constant(domain_byte as u64), // domain_byte in low byte
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
        Word64::constant(0),
    ];
    // Counter = 33 (total bytes: 32 sk + 1 domain_byte), final block.
    compress(cs, &mut h, &block, 33, true)?;

    Ok(h)
}

/// Convert 8 Word64 hash output to a flat vector of Boolean bits (512 bits, little-endian).
pub fn hash_to_bits<F: PrimeField>(h: &[Word64<F>; 8]) -> Vec<Boolean<F>> {
    let mut bits = Vec::with_capacity(512);
    for word in h {
        bits.extend_from_slice(&word.bits);
    }
    bits
}

/// Extract the first 256 bits (32 bytes) from a 512-bit hash output.
pub fn hash_first_256<F: PrimeField>(h: &[Word64<F>; 8]) -> Vec<Boolean<F>> {
    let mut bits = Vec::with_capacity(256);
    for word in &h[..4] {
        bits.extend_from_slice(&word.bits);
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_prf_expand_matches_blake2b_simd() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let sk = [0x42u8; 32];
        let domain = 0x06u8;

        // Compute expected result using blake2b_simd.
        // PRF_expand: msg = sk || domain_byte (no BLAKE2b key).
        let expected = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[domain]].concat());

        // Convert sk to Word64.
        let sk_words: [Word64<Fr>; 4] = [
            Word64::new_witness(cs.clone(), Some(u64::from_le_bytes(sk[0..8].try_into().unwrap())))
                .unwrap(),
            Word64::new_witness(
                cs.clone(),
                Some(u64::from_le_bytes(sk[8..16].try_into().unwrap())),
            )
            .unwrap(),
            Word64::new_witness(
                cs.clone(),
                Some(u64::from_le_bytes(sk[16..24].try_into().unwrap())),
            )
            .unwrap(),
            Word64::new_witness(
                cs.clone(),
                Some(u64::from_le_bytes(sk[24..32].try_into().unwrap())),
            )
            .unwrap(),
        ];

        let result = prf_expand(cs.clone(), &sk_words, domain).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Convert circuit result to bytes.
        let mut result_bytes = [0u8; 64];
        for (i, word) in result.iter().enumerate() {
            let val: u64 = word
                .bits
                .iter()
                .enumerate()
                .map(|(j, b)| {
                    if b.value().unwrap() {
                        1u64 << j
                    } else {
                        0
                    }
                })
                .sum();
            result_bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
        }

        assert_eq!(&result_bytes[..], expected.as_bytes());
    }
}
