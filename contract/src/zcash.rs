use blake2b_simd::Params;
use k256::{
    elliptic_curve::{bigint::U256, ops::Reduce, sec1::FromEncodedPoint},
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, PublicKey,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

const EPSILON_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = <Ripemd160 as Digest>::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

fn blake2b_personal(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = Params::new().hash_length(32).personal(personal).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

const P_HEADERS:    &[u8; 16] = b"ZTxIdHeadersHash";
const P_TRANSPARENT:&[u8; 16] = b"ZTxIdTranspaHash";
const P_PREVOUTS:   &[u8; 16] = b"ZTxIdPrevoutHash";
const P_SEQUENCES:  &[u8; 16] = b"ZTxIdSequencHash";
const P_OUTPUTS:    &[u8; 16] = b"ZTxIdOutputsHash";
const P_AMOUNTS:    &[u8; 16] = b"ZTxTrAmountsHash";
const P_SCRIPTS:    &[u8; 16] = b"ZTxTrScriptsHash";
const P_TXIN:       &[u8; 16] = b"Zcash___TxInHash";
const P_SAPLING:    &[u8; 16] = b"ZTxIdSaplingHash";
const P_ORCHARD:    &[u8; 16] = b"ZTxIdOrchardHash";
const P_ORCH_AC:    &[u8; 16] = b"ZTxIdOrcActCHash";
const P_ORCH_AM:    &[u8; 16] = b"ZTxIdOrcActMHash";
const P_ORCH_AN:    &[u8; 16] = b"ZTxIdOrcActNHash";

fn top_level_personal(branch_id: u32) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..12].copy_from_slice(b"ZcashTxHash_");
    p[12..].copy_from_slice(&branch_id.to_le_bytes());
    p
}

fn read_compact_size(data: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *data.get(*offset)?;
    *offset += 1;
    let val = match first {
        0..=252 => first as u64,
        253     => {
            let bytes = data.get(*offset..*offset + 2)?;
            *offset += 2;
            u16::from_le_bytes([bytes[0], bytes[1]]) as u64
        }
        254     => {
            let bytes = data.get(*offset..*offset + 4)?;
            *offset += 4;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
        }
        255     => {
            let bytes = data.get(*offset..*offset + 8)?;
            *offset += 8;
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        }
    };
    Some(val)
}

fn encode_compact_size(value: u64) -> Vec<u8> {
    if value <= 252 {
        vec![value as u8]
    } else if value <= 0xFFFF {
        let mut v = vec![253];
        v.extend_from_slice(&(value as u16).to_le_bytes());
        v
    } else if value <= 0xFFFF_FFFF {
        let mut v = vec![254];
        v.extend_from_slice(&(value as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![255];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }
}

fn read_u32_le(data: &[u8], offset: &mut usize) -> Option<u32> {
    let bytes = data.get(*offset..*offset + 4)?;
    *offset += 4;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i64_le(data: &[u8], offset: &mut usize) -> Option<i64> {
    let bytes = data.get(*offset..*offset + 8)?;
    *offset += 8;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Some(i64::from_le_bytes(buf))
}

fn read_bytes(data: &[u8], offset: &mut usize, n: usize) -> Option<Vec<u8>> {
    let v = data.get(*offset..*offset + n)?.to_vec();
    *offset += n;
    Some(v)
}

fn read_array<const N: usize>(data: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let bytes = data.get(*offset..*offset + N)?;
    *offset += N;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Some(out)
}

#[derive(Debug, Clone)]
pub struct TransparentInput {
    pub prevout_txid: [u8; 32],
    pub prevout_vout: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct OrchardAction {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: [u8; 80],
}

#[derive(Debug, Clone)]
pub struct OrchardBundle {
    pub actions: Vec<OrchardAction>,
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ParsedTx {
    pub version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub tx_in: TransparentInput,
    pub orchard: Option<OrchardBundle>,
}

pub fn parse_tx(raw: &[u8]) -> Result<ParsedTx, &'static str> {
    let mut c = 0usize;

    let version = read_u32_le(raw, &mut c).ok_or("short version")?;
    if version != 0x80000005 {
        return Err("not v5 overwintered");
    }
    let version_group_id = read_u32_le(raw, &mut c).ok_or("short vgid")?;
    if version_group_id != 0x26A7270A {
        return Err("bad version_group_id");
    }
    let consensus_branch_id = read_u32_le(raw, &mut c).ok_or("short branch")?;
    let lock_time = read_u32_le(raw, &mut c).ok_or("short lock_time")?;
    let expiry_height = read_u32_le(raw, &mut c).ok_or("short expiry")?;

    let tx_in_count = read_compact_size(raw, &mut c).ok_or("short tx_in_count")?;
    if tx_in_count != 1 {
        return Err("expected exactly 1 transparent input");
    }
    let prevout_txid = read_array(raw, &mut c).ok_or("short prevout txid")?;
    let prevout_vout = read_u32_le(raw, &mut c).ok_or("short prevout vout")?;
    let script_len = read_compact_size(raw, &mut c).ok_or("short script_sig len")? as usize;
    c = c.checked_add(script_len).ok_or("offset overflow")?;
    if c > raw.len() {
        return Err("script_sig truncated");
    }
    let sequence = read_u32_le(raw, &mut c).ok_or("short sequence")?;
    let tx_in = TransparentInput {
        prevout_txid,
        prevout_vout,
        sequence,
    };

    let tx_out_count = read_compact_size(raw, &mut c).ok_or("short tx_out_count")?;
    if tx_out_count != 0 {
        return Err("expected 0 transparent outputs");
    }

    let sapling_spend_count = read_compact_size(raw, &mut c).ok_or("short sapling spends")?;
    if sapling_spend_count != 0 {
        return Err("sapling spends must be empty");
    }
    let sapling_output_count = read_compact_size(raw, &mut c).ok_or("short sapling outputs")?;
    if sapling_output_count != 0 {
        return Err("sapling outputs must be empty");
    }

    let n_actions = read_compact_size(raw, &mut c).ok_or("short orchard actions")?;
    let orchard = if n_actions == 0 {
        None
    } else {
        let n = n_actions as usize;
        let mut actions = Vec::with_capacity(n);
        for _ in 0..n {
            let cv: [u8; 32]             = read_array(raw, &mut c).ok_or("short cv")?;
            let nullifier: [u8; 32]      = read_array(raw, &mut c).ok_or("short nullifier")?;
            let rk: [u8; 32]             = read_array(raw, &mut c).ok_or("short rk")?;
            let cmx: [u8; 32]            = read_array(raw, &mut c).ok_or("short cmx")?;
            let ephemeral_key: [u8; 32]  = read_array(raw, &mut c).ok_or("short ephemeralKey")?;
            let enc_ciphertext           = read_bytes(raw, &mut c, 580).ok_or("short encCiphertext")?;
            let out_ciphertext: [u8; 80] = read_array(raw, &mut c).ok_or("short outCiphertext")?;
            actions.push(OrchardAction {
                cv,
                nullifier,
                rk,
                cmx,
                ephemeral_key,
                enc_ciphertext,
                out_ciphertext,
            });
        }

        let flags = *raw.get(c).ok_or("short flags")?;
        c += 1;
        let value_balance = read_i64_le(raw, &mut c).ok_or("short value_balance")?;
        let anchor: [u8; 32] = read_array(raw, &mut c).ok_or("short anchor")?;

        let proofs_size = read_compact_size(raw, &mut c).ok_or("short proofs size")? as usize;
        c = c.checked_add(proofs_size).ok_or("offset overflow")?;
        if c > raw.len() {
            return Err("orchard proofs truncated");
        }
        let sigs_size = 64usize.checked_mul(n).ok_or("offset overflow")?;
        c = c.checked_add(sigs_size).ok_or("offset overflow")?;
        if c > raw.len() {
            return Err("orchard spend-auth sigs truncated");
        }
        c = c.checked_add(64).ok_or("offset overflow")?;
        if c > raw.len() {
            return Err("orchard binding sig truncated");
        }

        Some(OrchardBundle {
            actions,
            flags,
            value_balance,
            anchor,
        })
    };

    if c != raw.len() {
        return Err("trailing bytes after tx");
    }

    Ok(ParsedTx {
        version,
        version_group_id,
        consensus_branch_id,
        lock_time,
        expiry_height,
        tx_in,
        orchard,
    })
}

pub fn validate_burner_script(script: &[u8], burner_pubkey: &[u8; 33]) -> Result<(), &'static str> {
    if script.len() != 25 {
        return Err("scriptPubKey wrong length");
    }
    if script[0..3] != [0x76, 0xa9, 0x14] {
        return Err("not P2PKH prefix");
    }
    if script[23..25] != [0x88, 0xac] {
        return Err("not P2PKH suffix");
    }
    if script[3..23] != hash160(burner_pubkey) {
        return Err("scriptPubKey does not match burner pubkey");
    }
    Ok(())
}

const TADDR_VERSION_MAINNET: [u8; 2] = [0x1C, 0xB8];
const TADDR_VERSION_TESTNET: [u8; 2] = [0x1D, 0x25];

pub fn derive_burner(
    mpc_root_pubkey: &str,
    predecessor_account_id: &str,
    path: &str,
    mainnet: bool,
) -> Result<(String, [u8; 33]), &'static str> {
    let root_pk = parse_near_pubkey(mpc_root_pubkey)?;

    let mut hasher = Sha3_256::new();
    hasher.update(EPSILON_PREFIX.as_bytes());
    hasher.update(predecessor_account_id.as_bytes());
    hasher.update(b",");
    hasher.update(path.as_bytes());
    let epsilon_bytes: [u8; 32] = hasher.finalize().into();

    let epsilon =
        <k256::Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&epsilon_bytes));
    if bool::from(epsilon.is_zero()) {
        return Err("derived zero epsilon");
    }

    let child = (ProjectivePoint::from(*root_pk.as_affine())
        + (ProjectivePoint::GENERATOR * epsilon))
        .to_affine();

    let encoded = EncodedPoint::from(child).compress();
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err("derived burner pubkey wrong length");
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

fn parse_near_pubkey(input: &str) -> Result<PublicKey, &'static str> {
    let b58 = input
        .strip_prefix("secp256k1:")
        .ok_or("mpc_root_pubkey must start with secp256k1:")?;
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|_| "invalid base58 mpc_root_pubkey")?;
    if bytes.len() != 64 {
        return Err("mpc_root_pubkey payload must be 64 bytes");
    }

    let x = FieldBytes::from_slice(&bytes[..32]);
    let y = FieldBytes::from_slice(&bytes[32..]);
    let encoded = EncodedPoint::from_affine_coordinates(x, y, false);
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or("invalid secp256k1 point")?;
    PublicKey::from_affine(point).map_err(|_| "invalid secp256k1 public key")
}

pub fn compute_sighash_all(
    tx: &ParsedTx,
    utxo_value_zats: u64,
    utxo_script_pubkey: &[u8],
) -> [u8; 32] {
    let header = header_digest(tx);
    let trans = transparent_sig_digest(tx, utxo_value_zats, utxo_script_pubkey);
    let saplng = blake2b_personal(P_SAPLING, &[]);
    let orchrd = orchard_digest(tx);

    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&trans);
    buf.extend_from_slice(&saplng);
    buf.extend_from_slice(&orchrd);
    blake2b_personal(&top_level_personal(tx.consensus_branch_id), &buf)
}


fn header_digest(tx: &ParsedTx) -> [u8; 32] {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&tx.version.to_le_bytes());
    buf.extend_from_slice(&tx.version_group_id.to_le_bytes());
    buf.extend_from_slice(&tx.consensus_branch_id.to_le_bytes());
    buf.extend_from_slice(&tx.lock_time.to_le_bytes());
    buf.extend_from_slice(&tx.expiry_height.to_le_bytes());
    blake2b_personal(P_HEADERS, &buf)
}

fn transparent_sig_digest(
    tx: &ParsedTx,
    utxo_value_zats: u64,
    utxo_script_pubkey: &[u8],
) -> [u8; 32] {
    let prev_txid    = tx.tx_in.prevout_txid;
    let prev_vout_le = tx.tx_in.prevout_vout.to_le_bytes();
    let seq_le       = tx.tx_in.sequence.to_le_bytes();

    let mut prevouts_buf = Vec::with_capacity(36);
    prevouts_buf.extend_from_slice(&prev_txid);
    prevouts_buf.extend_from_slice(&prev_vout_le);
    let prevouts_sig = blake2b_personal(P_PREVOUTS, &prevouts_buf);

    let amounts_sig = blake2b_personal(P_AMOUNTS, &utxo_value_zats.to_le_bytes());

    let scripts_sig = {
        let mut buf = encode_compact_size(utxo_script_pubkey.len() as u64);
        buf.extend_from_slice(utxo_script_pubkey);
        blake2b_personal(P_SCRIPTS, &buf)
    };

    let sequence_sig = blake2b_personal(P_SEQUENCES, &seq_le);

    let outputs_sig = blake2b_personal(P_OUTPUTS, &[]);

    let mut txin_buf = Vec::with_capacity(64);
    txin_buf.extend_from_slice(&prev_txid);
    txin_buf.extend_from_slice(&prev_vout_le);
    txin_buf.extend_from_slice(&utxo_value_zats.to_le_bytes());
    txin_buf.extend_from_slice(&encode_compact_size(utxo_script_pubkey.len() as u64));
    txin_buf.extend_from_slice(utxo_script_pubkey);
    txin_buf.extend_from_slice(&seq_le);
    let txin_sig = blake2b_personal(P_TXIN, &txin_buf);

    let mut buf = Vec::with_capacity(1 + 32 * 6);
    buf.push(0x01);
    buf.extend_from_slice(&prevouts_sig);
    buf.extend_from_slice(&amounts_sig);
    buf.extend_from_slice(&scripts_sig);
    buf.extend_from_slice(&sequence_sig);
    buf.extend_from_slice(&outputs_sig);
    buf.extend_from_slice(&txin_sig);
    blake2b_personal(P_TRANSPARENT, &buf)
}

fn orchard_digest(tx: &ParsedTx) -> [u8; 32] {
    match &tx.orchard {
        None => blake2b_personal(P_ORCHARD, &[]),
        Some(b) => {
            let compact = orchard_actions_compact(&b.actions);
            let memos   = orchard_actions_memos(&b.actions);
            let nonc    = orchard_actions_noncompact(&b.actions);

            let mut buf = Vec::with_capacity(32 * 3 + 1 + 8 + 32);
            buf.extend_from_slice(&compact);
            buf.extend_from_slice(&memos);
            buf.extend_from_slice(&nonc);
            buf.push(b.flags);
            buf.extend_from_slice(&b.value_balance.to_le_bytes());
            buf.extend_from_slice(&b.anchor);
            blake2b_personal(P_ORCHARD, &buf)
        }
    }
}

fn orchard_actions_compact(actions: &[OrchardAction]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(actions.len() * (32 + 32 + 32 + 52));
    for a in actions {
        buf.extend_from_slice(&a.nullifier);
        buf.extend_from_slice(&a.cmx);
        buf.extend_from_slice(&a.ephemeral_key);
        buf.extend_from_slice(&a.enc_ciphertext[..52]);
    }
    blake2b_personal(P_ORCH_AC, &buf)
}

fn orchard_actions_memos(actions: &[OrchardAction]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(actions.len() * 512);
    for a in actions {
        buf.extend_from_slice(&a.enc_ciphertext[52..564]);
    }
    blake2b_personal(P_ORCH_AM, &buf)
}

fn orchard_actions_noncompact(actions: &[OrchardAction]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(actions.len() * (32 + 32 + 16 + 80));
    for a in actions {
        buf.extend_from_slice(&a.cv);
        buf.extend_from_slice(&a.rk);
        buf.extend_from_slice(&a.enc_ciphertext[564..580]);
        buf.extend_from_slice(&a.out_ciphertext);
    }
    blake2b_personal(P_ORCH_AN, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash160_len() {
        assert_eq!(hash160(b"hello").len(), 20);
    }

    #[test]
    fn compact_size_roundtrip() {
        for v in [0u64, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000] {
            let enc = encode_compact_size(v);
            let mut off = 0;
            let dec = read_compact_size(&enc, &mut off).unwrap();
            assert_eq!(v, dec);
            assert_eq!(off, enc.len());
        }
    }

    #[test]
    fn personal_strings_are_16_bytes() {
        for p in [
            P_HEADERS,
            P_TRANSPARENT,
            P_PREVOUTS,
            P_SEQUENCES,
            P_OUTPUTS,
            P_AMOUNTS,
            P_SCRIPTS,
            P_TXIN,
            P_SAPLING,
            P_ORCHARD,
            P_ORCH_AC,
            P_ORCH_AM,
            P_ORCH_AN,
        ] {
            assert_eq!(p.len(), 16);
        }
    }

    #[test]
    fn empty_sapling_digest_is_deterministic() {
        let a = blake2b_personal(P_SAPLING, &[]);
        let b = blake2b_personal(P_SAPLING, &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_burner_matches_mpc_logic() {
        let root = "secp256k1:3SB8tA9Kbn7FBtT6GWR6AJk73QceudisHaGThPoLCDgC9tan7d3cwZFiDZtrmhSAf8aTynEdQ3N7KXhMm3nWhekP";
        let account = "alice.near";
        let path = "zns-alice-0";

        let (contract_taddr, contract_pk) =
            derive_burner(root, account, path, false).expect("derive_burner failed");

        let root_pk = parse_near_pubkey(root).unwrap();

        let mut hasher = Sha3_256::new();
        hasher.update(EPSILON_PREFIX.as_bytes());
        hasher.update(account.as_bytes());
        hasher.update(b",");
        hasher.update(path.as_bytes());
        let tweak_bytes: [u8; 32] = hasher.finalize().into();

        use k256::elliptic_curve::PrimeField;
        let mpc_scalar =
            k256::Scalar::from_repr(*FieldBytes::from_slice(&tweak_bytes)).into_option();
        assert!(
            mpc_scalar.is_some(),
            "tweak hash >= secp256k1 order — MPC would reject this path"
        );
        let mpc_scalar = mpc_scalar.unwrap();
        assert!(
            !bool::from(mpc_scalar.is_zero()),
            "MPC derived zero scalar — contract would reject"
        );

        let contract_scalar =
            <k256::Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&tweak_bytes));
        assert_eq!(
            mpc_scalar, contract_scalar,
            "reduce_bytes disagrees with from_repr for this test vector"
        );

        let mpc_child = (ProjectivePoint::from(*root_pk.as_affine())
            + (ProjectivePoint::GENERATOR * mpc_scalar))
            .to_affine();
        let mpc_encoded = EncodedPoint::from(mpc_child).compress();
        let mpc_pk = mpc_encoded.as_bytes();
        assert_eq!(mpc_pk.len(), 33);

        let mpc_taddr = {
            let version = TADDR_VERSION_TESTNET;
            let mut payload = Vec::with_capacity(22);
            payload.extend_from_slice(&version);
            payload.extend_from_slice(&hash160(mpc_pk));
            bs58::encode(payload).with_check().into_string()
        };

        assert_eq!(
            contract_pk.as_slice(), mpc_pk,
            "contract pubkey does not match MPC-equivalent derivation"
        );
        assert_eq!(
            contract_taddr, mpc_taddr,
            "contract t-addr does not match MPC-equivalent derivation"
        );
    }

    #[test]
    fn derive_burner_mpc_tweak_snapshot_vector() {
        let account = "dwefqwg";
        let path = "frwewegwegweg";

        let mut hasher = Sha3_256::new();
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
            "contract tweak hash does not match NEAR MPC snapshot for known inputs"
        );
    }
}