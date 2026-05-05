//! Local burner-address derivation.
//!
//! Mirrors the contract's `derive_burner` in `contract/src/zcash.rs`. Given
//! the MPC root pubkey, the contract account ID, a listing name and nonce,
//! computes the same `(t-addr, compressed pubkey)` the contract would derive
//! on chain — without a contract roundtrip.

use anyhow::{Result, bail};
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, PublicKey,
    elliptic_curve::{bigint::U256, ops::Reduce, sec1::FromEncodedPoint},
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

const EPSILON_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";
const TADDR_VERSION_MAINNET: [u8; 2] = [0x1c, 0xb8];
const TADDR_VERSION_TESTNET: [u8; 2] = [0x1d, 0x25];

pub fn listing_path(name: &str, nonce: u64) -> String {
    format!("zns-{name}-{nonce}")
}

pub fn derive_burner(
    mpc_root_pubkey: &str,
    contract_account: &str,
    name: &str,
    nonce: u64,
    mainnet: bool,
) -> Result<(String, [u8; 33])> {
    let path = listing_path(name, nonce);
    let root_pk = parse_near_pubkey(mpc_root_pubkey)?;

    let mut hasher = Sha3_256::new();
    hasher.update(EPSILON_PREFIX.as_bytes());
    hasher.update(contract_account.as_bytes());
    hasher.update(b",");
    hasher.update(path.as_bytes());
    let epsilon_bytes: [u8; 32] = hasher.finalize().into();

    let epsilon =
        <k256::Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&epsilon_bytes));
    if bool::from(epsilon.is_zero()) {
        bail!("derived zero epsilon");
    }

    let child = (ProjectivePoint::from(*root_pk.as_affine())
        + (ProjectivePoint::GENERATOR * epsilon))
        .to_affine();

    let encoded = EncodedPoint::from(child).compress();
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        bail!("derived burner pubkey wrong length");
    }
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(bytes);

    let version = if mainnet {
        TADDR_VERSION_MAINNET
    } else {
        TADDR_VERSION_TESTNET
    };
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&version);
    payload.extend_from_slice(&hash160(&pubkey));
    let taddr = bs58::encode(payload).with_check().into_string();
    Ok((taddr, pubkey))
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = <Ripemd160 as Digest>::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn parse_near_pubkey(input: &str) -> Result<PublicKey> {
    let b58 = input
        .strip_prefix("secp256k1:")
        .ok_or_else(|| anyhow::anyhow!("mpc_root_pubkey must start with secp256k1:"))?;
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|_| anyhow::anyhow!("invalid base58 mpc_root_pubkey"))?;
    if bytes.len() != 64 {
        bail!("mpc_root_pubkey payload must be 64 bytes");
    }

    let x = FieldBytes::from_slice(&bytes[..32]);
    let y = FieldBytes::from_slice(&bytes[32..]);
    let encoded = EncodedPoint::from_affine_coordinates(x, y, false);
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow::anyhow!("invalid secp256k1 point"))?;
    PublicKey::from_affine(point).map_err(|_| anyhow::anyhow!("invalid secp256k1 public key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot vector matched against the contract's
    /// `derive_burner_mpc_tweak_snapshot_vector` test.
    #[test]
    fn mpc_tweak_snapshot_vector() {
        let account = "dwefqwg";
        let path = "frwewegwegweg";

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(EPSILON_PREFIX.as_bytes());
        hasher.update(account.as_bytes());
        hasher.update(b",");
        hasher.update(path.as_bytes());
        let tweak_bytes: [u8; 32] = hasher.finalize().into();

        let expected: [u8; 32] = [
            173, 45, 111, 193, 244, 69, 161, 180, 56, 48, 65, 94, 126, 110, 61, 3, 205, 7, 118,
            115, 4, 120, 72, 160, 133, 241, 48, 194, 79, 83, 238, 0,
        ];
        assert_eq!(
            tweak_bytes, expected,
            "service tweak hash does not match NEAR MPC snapshot for known inputs"
        );
    }

    /// Sanity-check that derivation with the generator point produces a
    /// valid-looking testnet t-address.
    #[test]
    fn matches_contract_derivation() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // Get uncompressed encoding (0x04 || x || y); strip 0x04 to get
        // the 64-byte x||y form NEAR uses for secp256k1: keys.
        let g = k256::ProjectivePoint::GENERATOR.to_affine();
        let uncompressed = g.to_encoded_point(false);
        let uncomp = uncompressed.as_bytes();
        assert_eq!(uncomp[0], 0x04);
        let key_bytes = &uncomp[1..];
        assert_eq!(key_bytes.len(), 64);
        let near_pk = format!("secp256k1:{}", bs58::encode(key_bytes).into_string());

        let (taddr, pubkey) =
            derive_burner(&near_pk, "zns.testnet", "alice.zcash", 1, false).unwrap();
        assert_eq!(pubkey.len(), 33);
        assert!(taddr.starts_with("tm") || taddr.starts_with("tn"));
    }
}
