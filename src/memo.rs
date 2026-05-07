// ZNS memo protocol — parse and validate memo-encoded actions.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zcash_address::ZcashAddress;

#[derive(Debug, Clone)]
pub struct MemoAction {
    pub name: String,
    pub signature: String,
    pub user_pubkey: Option<[u8; 32]>,
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

/// Constructs the ownership payload for a CLAIM or BUY establishing action.
///
/// Ownership proofs verify that the stored signature from the original CLAIM or BUY
/// still validates against a given key, proving sovereign control. The payload format
/// is `CLAIM:{name}:{ua}` or `BUY:{name}:{ua}` — same as the signing payload for
/// those actions (they have no nonce).
pub fn ownership_payload(action: &str, name: &str, ua: &str) -> Option<String> {
    match action {
        "CLAIM" => Some(format!("CLAIM:{name}:{ua}")),
        "BUY" => Some(format!("BUY:{name}:{ua}")),
        _ => None,
    }
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

// ── Signing payload construction (single source of truth) ────────────────────

/// Returns the signing payload for a given action, per the ZNS namespace spec.
///
/// This is the canonical construction used for both signature verification
/// and ownership proofs. The format is defined in NAMESPACE_SPEC.md §4:
///
/// | Action    | Signing payload format                    |
/// |-----------|-----------------------------------------|
/// | CLAIM     | `CLAIM:{name}:{ua}`                     |
/// | LIST      | `LIST:{name}:{price}:{nonce}`           |
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

fn parse_user_pubkey(s: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    bytes.try_into().ok()
}

/// Extract signature (second-to-last mandatory field) and optional user_pubkey
/// (trailing field if present) from a split parts array.
fn extract_sig_and_pubkey(parts: &[&str], sig_idx: usize) -> Option<(String, Option<[u8; 32]>)> {
    let sig = parts[sig_idx];
    let pk = parts.get(sig_idx + 1).and_then(|s| parse_user_pubkey(s));
    Some((sig.into(), pk))
}

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
        user_pubkey: None,
        kind: ActionKind::SetPrice { prices, nonce },
    })
}

fn parse_claim(rest: &str) -> Option<MemoAction> {
    // ZNS:CLAIM:<name>:<ua>:<sig>[:<user_pubkey>]
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    if parts.len() < 3 || !validate_name(parts[0]) || !validate_ua(parts[1]) {
        return None;
    }
    let (sig, pk) = extract_sig_and_pubkey(&parts, 2)?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: sig,
        user_pubkey: pk,
        kind: ActionKind::Claim { ua: parts[1].into() },
    })
}

fn parse_list(rest: &str) -> Option<MemoAction> {
    // ZNS:LIST:<name>:<price>:<pay_taddr>:<nonce>:<sig>[:<user_pubkey>]
    let parts: Vec<&str> = rest.splitn(6, ':').collect();
    if parts.len() < 5 || !validate_name(parts[0]) {
        return None;
    }
    let price: u64 = parts[1].parse().ok()?;
    let pay_taddr = parts[2].to_string();
    let nonce: u64 = parts[3].parse().ok()?;
    let (sig, pk) = extract_sig_and_pubkey(&parts, 4)?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: sig,
        user_pubkey: pk,
        kind: ActionKind::List { price, pay_taddr, nonce },
    })
}

fn parse_delist(rest: &str) -> Option<MemoAction> {
    // ZNS:DELIST:<name>:<nonce>:<sig>[:<user_pubkey>]
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    if parts.len() < 3 || !validate_name(parts[0]) {
        return None;
    }
    let nonce: u64 = parts[1].parse().ok()?;
    let (sig, pk) = extract_sig_and_pubkey(&parts, 2)?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: sig,
        user_pubkey: pk,
        kind: ActionKind::Delist { nonce },
    })
}

fn parse_release(rest: &str) -> Option<MemoAction> {
    // ZNS:RELEASE:<name>:<nonce>:<sig>[:<user_pubkey>]
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    if parts.len() < 3 || !validate_name(parts[0]) {
        return None;
    }
    let nonce: u64 = parts[1].parse().ok()?;
    let (sig, pk) = extract_sig_and_pubkey(&parts, 2)?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: sig,
        user_pubkey: pk,
        kind: ActionKind::Release { nonce },
    })
}

fn parse_update(rest: &str) -> Option<MemoAction> {
    // ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>[:<user_pubkey>]
    let parts: Vec<&str> = rest.splitn(5, ':').collect();
    if parts.len() < 4 || !validate_name(parts[0]) || !validate_ua(parts[1]) {
        return None;
    }
    let nonce: u64 = parts[2].parse().ok()?;
    let (sig, pk) = extract_sig_and_pubkey(&parts, 3)?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: sig,
        user_pubkey: pk,
        kind: ActionKind::Update { new_ua: parts[1].into(), nonce },
    })
}

fn parse_buy(rest: &str) -> Option<MemoAction> {
    // ZNS:BUY:<name>:<buyer_ua>:<price>:<sig>[:<user_pubkey>]
    let parts: Vec<&str> = rest.splitn(5, ':').collect();
    if parts.len() < 4 || !validate_name(parts[0]) || !validate_ua(parts[1]) {
        return None;
    }
    let buyer_ua = parts[1].to_string();
    let price: u64 = parts[2].parse().ok()?;
    let (sig, pk) = extract_sig_and_pubkey(&parts, 3)?;
    Some(MemoAction {
        name: parts[0].into(),
        signature: sig,
        user_pubkey: pk,
        kind: ActionKind::Buy { buyer_ua, price },
    })
}
