// ZNS memo protocol — parse and validate memo-encoded actions.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zcash_address::ZcashAddress;

#[derive(Debug, Clone)]
pub struct MemoAction {
    pub name: String,
    pub signature: String,
    pub kind: ActionKind,
}

#[derive(Debug, Clone)]
pub enum ActionKind {
    Claim { ua: String },
    List { price: u64, pay_taddr: String, nonce: u64 },
    Delist { nonce: u64 },
    Release { nonce: u64 },
    Update { new_ua: String, nonce: u64 },
    Buy { buyer_ua: String, price: u64 },
    SetPrice { prices: Vec<u64>, nonce: u64 },
}

impl ActionKind {}

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

pub fn normalize_name_query(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(stripped) = s.strip_suffix(".zcash") {
        s = stripped.to_string();
    } else if let Some(stripped) = s.strip_suffix(".zec") {
        s = stripped.to_string();
    }
    s
}

fn validate_taddr(taddr: &str) -> bool {
    if taddr.is_empty() || taddr.len() < 26 || taddr.len() > 36 {
        return false;
    }
    let valid_prefix = taddr.starts_with("t1")
        || taddr.starts_with("t3")
        || taddr.starts_with("tm")
        || taddr.starts_with("tn");
    if !valid_prefix {
        return false;
    }
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    taddr.chars().all(|c| BASE58.contains(c))
}

// ── Signing payload construction (single source of truth) ────────────────────

/// Returns the signing payload for a given action, per the ZNS namespace spec.
///
/// This is the canonical construction used for signature verification.
/// The format is defined in NAMESPACE_SPEC.md §4:
///
/// | Action    | Signing payload format                    |
/// |-----------|-----------------------------------------|
/// | CLAIM     | `CLAIM:{name}:{ua}`                     |
/// | LIST      | `LIST:{name}:{price}:{pay_taddr}:{nonce}` |
/// | DELIST    | `DELIST:{name}:{nonce}`                  |
/// | RELEASE   | `RELEASE:{name}:{nonce}`                 |
/// | UPDATE    | `UPDATE:{name}:{new_ua}:{nonce}`         |
/// | BUY       | `BUY:{name}:{buyer_ua}`                  |
/// | SETPRICE  | `SETPRICE:{count}:{tier1}:...:{nonce}`  |
pub fn signing_payload(action: &MemoAction) -> String {
    match &action.kind {
        ActionKind::Claim { ua } => format!("CLAIM:{}:{ua}", action.name),
        ActionKind::List { price, pay_taddr, nonce } => format!("LIST:{}:{price}:{pay_taddr}:{nonce}", action.name),
        ActionKind::Delist { nonce } => format!("DELIST:{}:{nonce}", action.name),
        ActionKind::Release { nonce } => format!("RELEASE:{}:{nonce}", action.name),
        ActionKind::Update { new_ua, nonce } => format!("UPDATE:{}:{new_ua}:{nonce}", action.name),
        ActionKind::Buy { buyer_ua, .. } => format!("BUY:{}:{buyer_ua}", action.name),
        ActionKind::SetPrice { prices, nonce } => {
            let count = prices.len();
            let prices_str: String = prices
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            format!("SETPRICE:{count}:{prices_str}:{nonce}")
        }
    }
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
    verify_signature(&signing_payload(action), &action.signature, pubkey)
}

// ── Parsing ──────────────────────────────────────────────────────────────────

pub fn parse_memo(memo: &[u8; 512]) -> Option<MemoAction> {
    let s = std::str::from_utf8(memo).ok()?;
    let s = s.trim_end_matches('\0').strip_prefix("ZNS:")?;
    let (action, rest) = s.split_once(':')?;

    match action {
        "SETPRICE" => parse_setprice(rest),
        "CLAIM"    => parse_claim(rest),
        "LIST"     => parse_list(rest),
        "DELIST"   => parse_delist(rest),
        "RELEASE"  => parse_release(rest),
        "UPDATE"   => parse_update(rest),
        "BUY"      => parse_buy(rest),
        _          => None,
    }
}

// ── Per-action parsers ───────────────────────────────────────────────────────

fn parse_setprice(rest: &str) -> Option<MemoAction> {
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
    let sig = parts[count + 2];
    Some(MemoAction {
        name: String::new(),
        signature: sig.into(),
        kind: ActionKind::SetPrice { prices, nonce },
    })
}

fn parse_claim(rest: &str) -> Option<MemoAction> {
    // ZNS:CLAIM:<name>:<ua>:<sig>
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    if parts.len() != 3 || !validate_name(parts[0]) || !validate_ua(parts[1]) {
        return None;
    }
    Some(MemoAction {
        name: parts[0].into(),
        signature: parts[2].into(),
        kind: ActionKind::Claim { ua: parts[1].into() },
    })
}

fn parse_list(rest: &str) -> Option<MemoAction> {
    // ZNS:LIST:<name>:<price>:<pay_taddr>:<nonce>:<sig>
    let parts: Vec<&str> = rest.splitn(5, ':').collect();
    if parts.len() != 5 || !validate_name(parts[0]) || !validate_taddr(parts[2]) {
        return None;
    }
    let price: u64 = parts[1].parse().ok()?;
    let pay_taddr = parts[2].to_string();
    let nonce: u64 = parts[3].parse().ok()?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: parts[4].into(),
        kind: ActionKind::List { price, pay_taddr, nonce },
    })
}

fn parse_delist(rest: &str) -> Option<MemoAction> {
    // ZNS:DELIST:<name>:<nonce>:<sig>
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    if parts.len() != 3 || !validate_name(parts[0]) {
        return None;
    }
    let nonce: u64 = parts[1].parse().ok()?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: parts[2].into(),
        kind: ActionKind::Delist { nonce },
    })
}

fn parse_release(rest: &str) -> Option<MemoAction> {
    // ZNS:RELEASE:<name>:<nonce>:<sig>
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    if parts.len() != 3 || !validate_name(parts[0]) {
        return None;
    }
    let nonce: u64 = parts[1].parse().ok()?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: parts[2].into(),
        kind: ActionKind::Release { nonce },
    })
}

fn parse_update(rest: &str) -> Option<MemoAction> {
    // ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    if parts.len() != 4 || !validate_name(parts[0]) || !validate_ua(parts[1]) {
        return None;
    }
    let nonce: u64 = parts[2].parse().ok()?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: parts[3].into(),
        kind: ActionKind::Update { new_ua: parts[1].into(), nonce },
    })
}

fn parse_buy(rest: &str) -> Option<MemoAction> {
    // ZNS:BUY:<name>:<buyer_ua>:<price>:<sig>
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    if parts.len() != 4 || !validate_name(parts[0]) || !validate_ua(parts[1]) {
        return None;
    }
    let buyer_ua = parts[1].to_string();
    let price: u64 = parts[2].parse().ok()?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: parts[3].into(),
        kind: ActionKind::Buy { buyer_ua, price },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_display_suffixes() {
        assert_eq!(normalize_name_query("alice.zcash"), "alice");
        assert_eq!(normalize_name_query("alice.zec"), "alice");
        assert_eq!(normalize_name_query("ALICE.ZCASH"), "alice");
        assert_eq!(normalize_name_query("  bob.zec  "), "bob");
    }

    #[test]
    fn normalize_preserves_bare_names() {
        assert_eq!(normalize_name_query("alice"), "alice");
        assert_eq!(normalize_name_query("user42"), "user42");
    }

    #[test]
    fn validate_name_rejects_invalid() {
        assert!(!validate_name(""));
        assert!(!validate_name("Alice"));
        assert!(!validate_name("my-name"));
        assert!(!validate_name(&"a".repeat(63)));
    }

    #[test]
    fn list_rejects_invalid_pay_taddr() {
        let memo = b"ZNS:LIST:alice:100000000:not-a-taddr:1:AQID\n";
        let mut padded = [0u8; 512];
        padded[..memo.len()].copy_from_slice(memo);
        assert!(parse_memo(&padded).is_none());
    }

    #[test]
    fn list_accepts_valid_pay_taddr() {
        let memo = b"ZNS:LIST:alice:100000000:tmqY61Gp3B7Pz3ev12NRFzWxJz1yB28Gfkfi:1:AQID\n";
        let mut padded = [0u8; 512];
        padded[..memo.len()].copy_from_slice(memo);
        let action = parse_memo(&padded).expect("parse LIST");
        assert!(matches!(action.kind, ActionKind::List { .. }));
    }
}
