// ZNS memo protocol — parse, validate, and authenticate memo-encoded actions.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zcash_address::ZcashAddress;

// TODO: replace with real Ed25519 pubkey before deploying
const ZNS_LISTING_PUBKEY: [u8; 32] = [0; 32];

pub enum MemoAction {
    Register { name: String, ua: String },
    List { name: String, price: u64, nonce: u64, signature: Vec<u8> },
    Delist { name: String, nonce: u64, signature: Vec<u8> },
    Update { name: String, new_ua: String, nonce: u64, signature: Vec<u8> },
    Buy { name: String, buyer_ua: String },
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
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ── Parsing ──────────────────────────────────────────────────────────────────

pub fn parse_memo(memo: &[u8; 512]) -> Option<MemoAction> {
    let s = std::str::from_utf8(memo).ok()?;
    let s = s.trim_end_matches('\0');

    if let Some(rest) = s.strip_prefix("ZNS:REGISTER:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 { return None; }
        let (name, ua) = (parts[0], parts[1]);
        if !validate_name(name) || !validate_ua(ua) { return None; }
        return Some(MemoAction::Register { name: name.into(), ua: ua.into() });
    }

    if let Some(rest) = s.strip_prefix("ZNS:LIST:") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 { return None; }
        let (name, price_str, nonce_str, sig_b64) = (parts[0], parts[1], parts[2], parts[3]);
        if !validate_name(name) { return None; }
        let price: u64 = price_str.parse().ok()?;
        let nonce: u64 = nonce_str.parse().ok()?;
        let signature = base64::engine::general_purpose::STANDARD.decode(sig_b64).ok()?;
        return Some(MemoAction::List { name: name.into(), price, nonce, signature });
    }

    if let Some(rest) = s.strip_prefix("ZNS:DELIST:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() != 3 { return None; }
        let (name, nonce_str, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) { return None; }
        let nonce: u64 = nonce_str.parse().ok()?;
        let signature = base64::engine::general_purpose::STANDARD.decode(sig_b64).ok()?;
        return Some(MemoAction::Delist { name: name.into(), nonce, signature });
    }

    if let Some(rest) = s.strip_prefix("ZNS:UPDATE:") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 { return None; }
        let (name, new_ua, nonce_str, sig_b64) = (parts[0], parts[1], parts[2], parts[3]);
        if !validate_name(name) || !validate_ua(new_ua) { return None; }
        let nonce: u64 = nonce_str.parse().ok()?;
        let signature = base64::engine::general_purpose::STANDARD.decode(sig_b64).ok()?;
        return Some(MemoAction::Update { name: name.into(), new_ua: new_ua.into(), nonce, signature });
    }

    if let Some(rest) = s.strip_prefix("ZNS:BUY:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 { return None; }
        let (name, buyer_ua) = (parts[0], parts[1]);
        if !validate_name(name) || !validate_ua(buyer_ua) { return None; }
        return Some(MemoAction::Buy { name: name.into(), buyer_ua: buyer_ua.into() });
    }

    None
}

// ── Signature verification ───────────────────────────────────────────────────

pub fn verify_signed_action(payload: &str, sig_bytes: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&ZNS_LISTING_PUBKEY) else { return false };
    verify_signed_action_with_key(&vk, payload, sig_bytes)
}

pub fn verify_signed_action_with_key(vk: &VerifyingKey, payload: &str, sig_bytes: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(sig_bytes) else { return false };
    vk.verify(payload.as_bytes(), &sig).is_ok()
}