/// Schnorr signature over Pallas curve for spend-key authentication.
///
/// Signs with `ask` (spend authorization scalar), verifies against `ak`.
/// Uses deterministic nonces (BLAKE2b-based) for safety.
///
/// The Schnorr message binds `ak || blind_point || binding_hash` to prevent
/// any component from being substituted between the Schnorr and Groth16 proofs.
use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;

/// A Schnorr signature: (R, s) where R is a compressed point and s is a scalar.
#[derive(Clone, Debug)]
pub struct SchnorrSignature {
    pub r_bytes: [u8; 32],
    pub s_bytes: [u8; 32],
}

impl SchnorrSignature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r_bytes);
        out[32..].copy_from_slice(&self.s_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[..32]);
        s_bytes.copy_from_slice(&bytes[32..]);
        SchnorrSignature { r_bytes, s_bytes }
    }
}

/// Build the Schnorr message that binds ak, blind_point, and binding_hash.
pub fn build_schnorr_message(
    ak_bytes: &[u8; 32],
    blind_point_bytes: &[u8; 32],
    binding_hash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(96);
    msg.extend_from_slice(ak_bytes);
    msg.extend_from_slice(blind_point_bytes);
    msg.extend_from_slice(binding_hash);
    msg
}

/// SpendAuthBase generator: GroupHash^P("z.cash:Orchard", "G").
fn spend_auth_base() -> pallas::Point {
    pallas::Point::hash_to_curve("z.cash:Orchard")(b"G")
}

/// Compute deterministic nonce: r = H(ask || msg) mod r_P.
/// Personalization ensures domain separation from other BLAKE2b uses.
fn deterministic_nonce(ask_bytes: &[u8; 32], msg: &[u8]) -> pallas::Scalar {
    let mut input = Vec::with_capacity(32 + msg.len());
    input.extend_from_slice(ask_bytes);
    input.extend_from_slice(msg);

    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ZNS:schnorr_nonc")
        .hash(&input);

    pallas::Scalar::from_uniform_bytes(hash.as_bytes().try_into().unwrap())
}

/// Compute Schnorr challenge: e = H(R || ak || msg) mod r_P.
fn challenge(r_bytes: &[u8; 32], ak_bytes: &[u8; 32], msg: &[u8]) -> pallas::Scalar {
    let mut input = Vec::with_capacity(64 + msg.len());
    input.extend_from_slice(r_bytes);
    input.extend_from_slice(ak_bytes);
    input.extend_from_slice(msg);

    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ZNS:schnorr_chal")
        .hash(&input);

    pallas::Scalar::from_uniform_bytes(hash.as_bytes().try_into().unwrap())
}

/// Sign a message with ask.
///
/// - `ask`: spend authorization scalar (derived from sk via PRF_expand)
/// - `msg`: message to sign (use `build_schnorr_message` output)
pub fn schnorr_sign(ask: &pallas::Scalar, msg: &[u8]) -> SchnorrSignature {
    use ff::PrimeField;

    let g = spend_auth_base();
    let ask_bytes: [u8; 32] = ask.to_repr();

    // Deterministic nonce
    let r = deterministic_nonce(&ask_bytes, msg);
    let r_point = g * r;
    let r_bytes: [u8; 32] = r_point.to_bytes().as_ref().try_into().unwrap();

    // ak = [ask] * G
    let ak = g * ask;
    let ak_bytes: [u8; 32] = ak.to_bytes().as_ref().try_into().unwrap();

    // Challenge
    let e = challenge(&r_bytes, &ak_bytes, msg);

    // s = r + e * ask
    let s = r + e * ask;
    let s_bytes: [u8; 32] = s.to_repr();

    SchnorrSignature { r_bytes, s_bytes }
}

/// Verify a Schnorr signature against ak.
///
/// - `ak_bytes`: compressed ak point (32 bytes)
/// - `msg`: the signed message
/// - `sig`: the signature
pub fn schnorr_verify(
    ak_bytes: &[u8; 32],
    msg: &[u8],
    sig: &SchnorrSignature,
) -> bool {
    let g = spend_auth_base();

    // Parse ak — GroupEncoding::from_bytes takes &Self::Repr
    let ak_repr: <pallas::Point as GroupEncoding>::Repr = (*ak_bytes).into();
    let ak_ct = pallas::Point::from_bytes(&ak_repr);
    if bool::from(ak_ct.is_none()) {
        return false;
    }
    let ak = ak_ct.unwrap();

    // Parse R
    let r_ct = pallas::Point::from_bytes(&sig.r_bytes);
    if bool::from(r_ct.is_none()) {
        return false;
    }
    let r_point = r_ct.unwrap();

    // Parse s
    let s_ct = pallas::Scalar::from_repr(sig.s_bytes);
    if bool::from(s_ct.is_none()) {
        return false;
    }
    let s = s_ct.unwrap();

    // Challenge
    let e = challenge(&sig.r_bytes, ak_bytes, msg);

    // Verify: [s] * G == R + [e] * ak
    let lhs = g * s;
    let rhs = r_point + ak * e;

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;

    fn test_ask() -> pallas::Scalar {
        let sk: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];
        let prf = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x06u8]].concat());
        pallas::Scalar::from_uniform_bytes(prf.as_bytes().try_into().unwrap())
    }

    #[test]
    fn test_schnorr_roundtrip() {
        let ask = test_ask();
        let msg = b"test message for schnorr";
        let sig = schnorr_sign(&ask, msg);

        let g = spend_auth_base();
        let ak = g * ask;
        let ak_bytes: [u8; 32] = ak.to_bytes().into();

        assert!(schnorr_verify(&ak_bytes, msg, &sig));
    }

    #[test]
    fn test_schnorr_deterministic() {
        let ask = test_ask();
        let msg = b"deterministic nonce test";
        let sig1 = schnorr_sign(&ask, msg);
        let sig2 = schnorr_sign(&ask, msg);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_schnorr_wrong_message() {
        let ask = test_ask();
        let sig = schnorr_sign(&ask, b"original message");

        let g = spend_auth_base();
        let ak = g * ask;
        let ak_bytes: [u8; 32] = ak.to_bytes().into();

        assert!(!schnorr_verify(&ak_bytes, b"tampered message", &sig));
    }

    #[test]
    fn test_schnorr_wrong_key() {
        let ask = test_ask();
        let sig = schnorr_sign(&ask, b"some message");

        // Use a different key for verification
        let wrong_ak = spend_auth_base() * pallas::Scalar::from(42u64);
        let wrong_ak_bytes: [u8; 32] = wrong_ak.to_bytes().into();

        assert!(!schnorr_verify(&wrong_ak_bytes, b"some message", &sig));
    }

    #[test]
    fn test_schnorr_serialization() {
        let ask = test_ask();
        let sig = schnorr_sign(&ask, b"serialize me");
        let bytes = sig.to_bytes();
        let sig2 = SchnorrSignature::from_bytes(&bytes);
        assert_eq!(sig.r_bytes, sig2.r_bytes);
        assert_eq!(sig.s_bytes, sig2.s_bytes);
    }

    #[test]
    fn test_build_schnorr_message() {
        let ak = [0xAAu8; 32];
        let bp = [0xBBu8; 32];
        let bh = [0xCCu8; 32];
        let msg = build_schnorr_message(&ak, &bp, &bh);
        assert_eq!(msg.len(), 96);
        assert_eq!(&msg[..32], &ak);
        assert_eq!(&msg[32..64], &bp);
        assert_eq!(&msg[64..], &bh);
    }
}
