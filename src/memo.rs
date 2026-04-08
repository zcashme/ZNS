// ZNS memo protocol — parse and validate memo-encoded actions.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zcash_address::ZcashAddress;

pub struct MemoAction {
    pub name: String,
    pub signature: String,
    pub user_pubkey: Option<[u8; 32]>,
    pub kind: ActionKind,
}

pub enum ActionKind {
    Claim { ua: String },
    List { price: u64, nonce: u64 },
    Delist { nonce: u64 },
    Release { nonce: u64 },
    Update { new_ua: String, nonce: u64 },
    Buy { buyer_ua: String },
    SetPrice { prices: Vec<u64>, nonce: u64 },
}

// ── Validation ───────────────────────────────────────────────────────────────

fn validate_ua(ua: &str) -> bool {
    ua.parse::<ZcashAddress>().is_ok()
}

pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 62
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

// ── Signature verification ───────────────────────────────────────────────────

pub fn verify_signature(payload: &str, sig_b64: &str, pubkey: &[u8; 32]) -> bool {
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(sig_b64) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    vk.verify(payload.as_bytes(), &sig).is_ok()
}

pub fn verify_action(action: &MemoAction, pubkey: &[u8; 32]) -> bool {
    let payload = match &action.kind {
        ActionKind::Claim { ua } => format!("CLAIM:{}:{ua}", action.name),
        ActionKind::List { price, nonce } => format!("LIST:{}:{price}:{nonce}", action.name),
        ActionKind::Delist { nonce } => format!("DELIST:{}:{nonce}", action.name),
        ActionKind::Release { nonce } => format!("RELEASE:{}:{nonce}", action.name),
        ActionKind::Update { new_ua, nonce } => format!("UPDATE:{}:{new_ua}:{nonce}", action.name),
        ActionKind::Buy { buyer_ua } => format!("BUY:{}:{buyer_ua}", action.name),
        ActionKind::SetPrice { prices, nonce } => {
            let count = prices.len();
            let prices_str: String = prices
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            format!("SETPRICE:{count}:{prices_str}:{nonce}")
        }
    };
    verify_signature(&payload, &action.signature, pubkey)
}

// ── Parsing ──────────────────────────────────────────────────────────────────

fn parse_user_pubkey(s: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    bytes.try_into().ok()
}

pub fn parse_memo(memo: &[u8; 512]) -> Option<MemoAction> {
    let s = std::str::from_utf8(memo).ok()?;
    let s = s.trim_end_matches('\0');

    if let Some(rest) = s.strip_prefix("ZNS:SETPRICE:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        let count: usize = parts[0].parse().ok()?;
        if parts.len() != count + 3 {
            return None;
        }
        let mut prices = Vec::with_capacity(count);
        for p in &parts[1..=count] {
            prices.push(p.parse::<u64>().ok()?);
        }
        let nonce: u64 = parts[count + 1].parse().ok()?;
        let sig_b64 = parts[count + 2];

        return Some(MemoAction {
            name: String::new(),
            signature: sig_b64.into(),
            user_pubkey: None,
            kind: ActionKind::SetPrice { prices, nonce },
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:CLAIM:") {
        // ZNS:CLAIM:<name>:<ua>:<sig>[:<user_pubkey>]
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() < 3 {
            return None;
        }
        let (name, ua, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) || !validate_ua(ua) {
            return None;
        }
        let user_pubkey = parts.get(3).and_then(|s| parse_user_pubkey(s));
        return Some(MemoAction {
            name: name.into(),
            signature: sig_b64.into(),
            user_pubkey,
            kind: ActionKind::Claim { ua: ua.into() },
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:LIST:") {
        // ZNS:LIST:<name>:<price>:<nonce>:<sig>[:<user_pubkey>]
        let parts: Vec<&str> = rest.splitn(5, ':').collect();
        if parts.len() < 4 {
            return None;
        }
        let (name, price_str, nonce_str, sig_b64) = (parts[0], parts[1], parts[2], parts[3]);
        if !validate_name(name) {
            return None;
        }
        let price: u64 = price_str.parse().ok()?;
        let nonce: u64 = nonce_str.parse().ok()?;
        let user_pubkey = parts.get(4).and_then(|s| parse_user_pubkey(s));
        return Some(MemoAction {
            name: name.into(),
            signature: sig_b64.into(),
            user_pubkey,
            kind: ActionKind::List { price, nonce },
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:DELIST:") {
        // ZNS:DELIST:<name>:<nonce>:<sig>[:<user_pubkey>]
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() < 3 {
            return None;
        }
        let (name, nonce_str, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) {
            return None;
        }
        let nonce: u64 = nonce_str.parse().ok()?;
        let user_pubkey = parts.get(3).and_then(|s| parse_user_pubkey(s));
        return Some(MemoAction {
            name: name.into(),
            signature: sig_b64.into(),
            user_pubkey,
            kind: ActionKind::Delist { nonce },
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:RELEASE:") {
        // ZNS:RELEASE:<name>:<nonce>:<sig>[:<user_pubkey>]
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() < 3 {
            return None;
        }
        let (name, nonce_str, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) {
            return None;
        }
        let nonce: u64 = nonce_str.parse().ok()?;
        let user_pubkey = parts.get(3).and_then(|s| parse_user_pubkey(s));
        return Some(MemoAction {
            name: name.into(),
            signature: sig_b64.into(),
            user_pubkey,
            kind: ActionKind::Release { nonce },
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:UPDATE:") {
        // ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>[:<user_pubkey>]
        let parts: Vec<&str> = rest.splitn(5, ':').collect();
        if parts.len() < 4 {
            return None;
        }
        let (name, new_ua, nonce_str, sig_b64) = (parts[0], parts[1], parts[2], parts[3]);
        if !validate_name(name) || !validate_ua(new_ua) {
            return None;
        }
        let nonce: u64 = nonce_str.parse().ok()?;
        let user_pubkey = parts.get(4).and_then(|s| parse_user_pubkey(s));
        return Some(MemoAction {
            name: name.into(),
            signature: sig_b64.into(),
            user_pubkey,
            kind: ActionKind::Update {
                new_ua: new_ua.into(),
                nonce,
            },
        });
    }

    if let Some(rest) = s.strip_prefix("ZNS:BUY:") {
        // ZNS:BUY:<name>:<buyer_ua>:<sig>[:<user_pubkey>]
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() < 3 {
            return None;
        }
        let (name, buyer_ua, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) || !validate_ua(buyer_ua) {
            return None;
        }
        let user_pubkey = parts.get(3).and_then(|s| parse_user_pubkey(s));
        return Some(MemoAction {
            name: name.into(),
            signature: sig_b64.into(),
            user_pubkey,
            kind: ActionKind::Buy {
                buyer_ua: buyer_ua.into(),
            },
        });
    }

    None
}
