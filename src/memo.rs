// ZNS memo protocol — parse, validate, and authenticate memo-encoded actions.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zcash_address::ZcashAddress;


pub enum MemoAction {
    Claim {
        name: String,
        ua: String,
    },
    List {
        name: String,
        price: u64,
        nonce: u64,
        signature: String,
    },
    Delist {
        name: String,
        nonce: u64,
        signature: String,
    },
    Update {
        name: String,
        new_ua: String,
        nonce: u64,
        signature: String,
    },
    Buy {
        name: String,
        buyer_ua: String,
    },
}

// ── Pricing ─────────────────────────────────────────────────────────────────

/// Returns the claim cost in zatoshis based on name length.
pub fn claim_cost(name_len: usize) -> u64 {
    match name_len {
        1 => 600_000_000, // 6 ZEC
        2 => 425_000_000, // 4.25 ZEC
        3 => 300_000_000, // 3 ZEC
        4 => 150_000_000, // 1.5 ZEC
        5 => 75_000_000,  // 0.75 ZEC
        6 => 50_000_000,  // 0.50 ZEC
        _ => 25_000_000,  // 0.25 ZEC (7+)
    }
}

// ── Validation ───────────────────────────────────────────────────────────────

fn validate_ua(ua: &str) -> bool {
    ua.parse::<ZcashAddress>().is_ok()
}

pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 62
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ── Parsing ──────────────────────────────────────────────────────────────────

pub fn parse_memo(memo: &[u8; 512], admin_pubkey: &[u8; 32]) -> Option<MemoAction> {
    let s = std::str::from_utf8(memo).ok()?;
    let s = s.trim_end_matches('\0');

    if let Some(rest) = s.strip_prefix("ZNS:CLAIM:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        let (name, ua) = (parts[0], parts[1]);
        if !validate_name(name) || !validate_ua(ua) {
            return None;
        }
        return Some(MemoAction::Claim {
            name: name.into(),
            ua: ua.into(),
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:LIST:") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 {
            return None;
        }
        let (name, price_str, nonce_str, sig_b64) = (parts[0], parts[1], parts[2], parts[3]);
        if !validate_name(name) {
            return None;
        }
        let price: u64 = price_str.parse().ok()?;
        let nonce: u64 = nonce_str.parse().ok()?;
        let payload = format!("LIST:{name}:{price}:{nonce}");
        verify_signature(&payload, sig_b64, admin_pubkey)?;
        return Some(MemoAction::List {
            name: name.into(),
            price,
            nonce,
            signature: sig_b64.into(),
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:DELIST:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() != 3 {
            return None;
        }
        let (name, nonce_str, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) {
            return None;
        }
        let nonce: u64 = nonce_str.parse().ok()?;
        let payload = format!("DELIST:{name}:{nonce}");
        verify_signature(&payload, sig_b64, admin_pubkey)?;
        return Some(MemoAction::Delist {
            name: name.into(),
            nonce,
            signature: sig_b64.into(),
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:UPDATE:") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 {
            return None;
        }
        let (name, new_ua, nonce_str, sig_b64) = (parts[0], parts[1], parts[2], parts[3]);
        if !validate_name(name) || !validate_ua(new_ua) {
            return None;
        }
        let nonce: u64 = nonce_str.parse().ok()?;
        let payload = format!("UPDATE:{name}:{new_ua}:{nonce}");
        verify_signature(&payload, sig_b64, admin_pubkey)?;
        return Some(MemoAction::Update {
            name: name.into(),
            new_ua: new_ua.into(),
            nonce,
            signature: sig_b64.into(),
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:BUY:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        let (name, buyer_ua) = (parts[0], parts[1]);
        if !validate_name(name) || !validate_ua(buyer_ua) {
            return None;
        }
        return Some(MemoAction::Buy {
            name: name.into(),
            buyer_ua: buyer_ua.into(),
        });
    }

    None
}

// ── Signature verification ───────────────────────────────────────────────────

fn verify_signature(payload: &str, sig_b64: &str, admin_pubkey: &[u8; 32]) -> Option<()> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .ok()?;
    let vk = VerifyingKey::from_bytes(admin_pubkey).ok()?;
    let sig = Signature::from_slice(&sig_bytes).ok()?;
    vk.verify(payload.as_bytes(), &sig).ok()
}
