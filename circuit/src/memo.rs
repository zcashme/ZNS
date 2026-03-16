/// Binary memo format for ZNS binding proofs.
///
/// Layout (≤512 bytes):
/// ```text
/// [1 byte]   action type (0x01=REGISTER, 0x02=LIST, 0x03=BID, 0x04=REFUND)
/// [1 byte]   name length
/// [N bytes]  name (UTF-8)
/// [43 bytes] raw Orchard receiver (11-byte diversifier + 32-byte pk_d)
/// [32 bytes] ak (compressed Pallas point)
/// [32 bytes] blind_point (compressed Pallas point)
/// [64 bytes] Schnorr signature (R || s)
/// [192 bytes] Groth16 proof (compressed)
/// ```
/// Total: 365 + N bytes. Fits for names up to ~140 chars.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZnsAction {
    Register = 0x01,
    List = 0x02,
    Bid = 0x03,
    Refund = 0x04,
}

impl ZnsAction {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(ZnsAction::Register),
            0x02 => Some(ZnsAction::List),
            0x03 => Some(ZnsAction::Bid),
            0x04 => Some(ZnsAction::Refund),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZnsMemo {
    pub action: ZnsAction,
    pub name: String,
    pub receiver: [u8; 43],
    pub ak: [u8; 32],
    pub blind_point: [u8; 32],
    pub schnorr_sig: [u8; 64],
    pub groth16_proof: Vec<u8>,
}

/// Fixed overhead: action(1) + name_len(1) + receiver(43) + ak(32) + blind_point(32) + sig(64) + proof(192) = 365
const FIXED_OVERHEAD: usize = 1 + 1 + 43 + 32 + 32 + 64;

impl ZnsMemo {
    pub fn encode(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        assert!(name_bytes.len() <= 255, "name too long");

        let mut buf = Vec::with_capacity(FIXED_OVERHEAD + name_bytes.len() + self.groth16_proof.len());
        buf.push(self.action as u8);
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.receiver);
        buf.extend_from_slice(&self.ak);
        buf.extend_from_slice(&self.blind_point);
        buf.extend_from_slice(&self.schnorr_sig);
        buf.extend_from_slice(&self.groth16_proof);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }

        let action = ZnsAction::from_byte(data[0])?;
        let name_len = data[1] as usize;
        let min_len = 2 + name_len + 43 + 32 + 32 + 64;
        if data.len() < min_len {
            return None;
        }

        let mut offset = 2;
        let name = String::from_utf8(data[offset..offset + name_len].to_vec()).ok()?;
        offset += name_len;

        let mut receiver = [0u8; 43];
        receiver.copy_from_slice(&data[offset..offset + 43]);
        offset += 43;

        let mut ak = [0u8; 32];
        ak.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut blind_point = [0u8; 32];
        blind_point.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut schnorr_sig = [0u8; 64];
        schnorr_sig.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;

        let groth16_proof = data[offset..].to_vec();

        Some(ZnsMemo {
            action,
            name,
            receiver,
            ak,
            blind_point,
            schnorr_sig,
            groth16_proof,
        })
    }

    /// Diversifier bytes (first 11 bytes of receiver).
    pub fn diversifier(&self) -> &[u8; 11] {
        self.receiver[..11].try_into().unwrap()
    }

    /// pk_d compressed bytes (last 32 bytes of receiver).
    pub fn pk_d_bytes(&self) -> &[u8; 32] {
        self.receiver[11..43].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memo_roundtrip() {
        let memo = ZnsMemo {
            action: ZnsAction::Register,
            name: "jules".to_string(),
            receiver: [0xAA; 43],
            ak: [0xBB; 32],
            blind_point: [0xCC; 32],
            schnorr_sig: [0xDD; 64],
            groth16_proof: vec![0xEE; 192],
        };

        let encoded = memo.encode();
        // 2 (header) + 5 (name) + 43 + 32 + 32 + 64 + 192 = 370
        assert_eq!(encoded.len(), 2 + 5 + 43 + 32 + 32 + 64 + 192);
        assert!(encoded.len() <= 512);

        let decoded = ZnsMemo::decode(&encoded).unwrap();
        assert_eq!(decoded.action, ZnsAction::Register);
        assert_eq!(decoded.name, "jules");
        assert_eq!(decoded.receiver, [0xAA; 43]);
        assert_eq!(decoded.ak, [0xBB; 32]);
        assert_eq!(decoded.blind_point, [0xCC; 32]);
        assert_eq!(decoded.schnorr_sig, [0xDD; 64]);
        assert_eq!(decoded.groth16_proof, vec![0xEE; 192]);
    }

    #[test]
    fn test_memo_max_name_length() {
        // Total = 2 + name_len + 43 + 32 + 32 + 64 + 192 = 365 + name_len
        // 365 + name_len <= 512 → name_len <= 147
        let max_name_len = 512 - 2 - 43 - 32 - 32 - 64 - 192;
        assert_eq!(max_name_len, 147);
        let name = "a".repeat(max_name_len);
        let memo = ZnsMemo {
            action: ZnsAction::Register,
            name,
            receiver: [0; 43],
            ak: [0; 32],
            blind_point: [0; 32],
            schnorr_sig: [0; 64],
            groth16_proof: vec![0; 192],
        };
        let encoded = memo.encode();
        assert_eq!(encoded.len(), 512);
    }

    #[test]
    fn test_memo_action_types() {
        for (byte, expected) in [
            (0x01, ZnsAction::Register),
            (0x02, ZnsAction::List),
            (0x03, ZnsAction::Bid),
            (0x04, ZnsAction::Refund),
        ] {
            assert_eq!(ZnsAction::from_byte(byte), Some(expected));
        }
        assert_eq!(ZnsAction::from_byte(0x00), None);
        assert_eq!(ZnsAction::from_byte(0xFF), None);
    }

    #[test]
    fn test_memo_decode_short_data() {
        assert!(ZnsMemo::decode(&[]).is_none());
        assert!(ZnsMemo::decode(&[0x01]).is_none());
        assert!(ZnsMemo::decode(&[0x01, 0x05]).is_none()); // name_len=5 but no data
    }

    #[test]
    fn test_memo_receiver_accessors() {
        let mut receiver = [0u8; 43];
        receiver[..11].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        receiver[11..].copy_from_slice(&[0xFF; 32]);

        let memo = ZnsMemo {
            action: ZnsAction::Register,
            name: "test".to_string(),
            receiver,
            ak: [0; 32],
            blind_point: [0; 32],
            schnorr_sig: [0; 64],
            groth16_proof: vec![],
        };

        assert_eq!(memo.diversifier(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        assert_eq!(memo.pk_d_bytes(), &[0xFF; 32]);
    }
}
