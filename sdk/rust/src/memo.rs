//! Memo builders and signing payloads for ZNS actions.
//!
//! Pure string formatters that mirror the action protocol in
//! `ZNS/src/memo.rs`. No network calls, no ownership of signing keys,
//! no validation beyond what `format!` requires. Keep the formats in
//! lockstep with `memo.rs` — any divergence means clients produce
//! memos the indexer will reject.
//!
//! ## Typical signed-action flow
//!
//! ```ignore
//! // 1. Get the bytes to sign.
//! let payload = list_payload("alice", 50_000_000, 3);
//!
//! // 2. Sign them with the admin Ed25519 key (out of scope for this SDK).
//! let sig_bytes: [u8; 64] = admin_key.sign(payload.as_bytes());
//!
//! // 3. Base64-encode the signature.
//! use base64::Engine;
//! let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
//!
//! // 4. Build the memo and stuff it into a Zcash transaction.
//! let memo = build_list_memo("alice", 50_000_000, 3, &sig_b64);
//! ```

// ── CLAIM ────────────────────────────────────────────────────────────────────

/// Bytes to sign for a CLAIM action: `"CLAIM:{name}:{ua}"`.
pub fn claim_payload(name: &str, ua: &str) -> String {
    format!("CLAIM:{name}:{ua}")
}

/// Build the memo for a CLAIM action.
pub fn build_claim_memo(
    name: &str,
    ua: &str,
    signature_b64: &str,
    user_pubkey: Option<&str>,
) -> String {
    let base = format!("ZNS:CLAIM:{name}:{ua}:{signature_b64}");
    match user_pubkey {
        Some(pk) => format!("{base}:{pk}"),
        None => base,
    }
}

// ── LIST ─────────────────────────────────────────────────────────────────────

/// Bytes to sign for a LIST action: `"LIST:{name}:{price}:{nonce}"`.
pub fn list_payload(name: &str, price: u64, nonce: u64) -> String {
    format!("LIST:{name}:{price}:{nonce}")
}

/// Build the memo for a LIST action.
pub fn build_list_memo(
    name: &str,
    price: u64,
    nonce: u64,
    signature_b64: &str,
    user_pubkey: Option<&str>,
) -> String {
    let base = format!("ZNS:LIST:{name}:{price}:{nonce}:{signature_b64}");
    match user_pubkey {
        Some(pk) => format!("{base}:{pk}"),
        None => base,
    }
}

// ── DELIST ───────────────────────────────────────────────────────────────────

/// Bytes to sign for a DELIST action: `"DELIST:{name}:{nonce}"`.
pub fn delist_payload(name: &str, nonce: u64) -> String {
    format!("DELIST:{name}:{nonce}")
}

/// Build the memo for a DELIST action.
pub fn build_delist_memo(
    name: &str,
    nonce: u64,
    signature_b64: &str,
    user_pubkey: Option<&str>,
) -> String {
    let base = format!("ZNS:DELIST:{name}:{nonce}:{signature_b64}");
    match user_pubkey {
        Some(pk) => format!("{base}:{pk}"),
        None => base,
    }
}

// ── RELEASE ──────────────────────────────────────────────────────────────────

/// Bytes to sign for a RELEASE action: `"RELEASE:{name}:{nonce}"`.
pub fn release_payload(name: &str, nonce: u64) -> String {
    format!("RELEASE:{name}:{nonce}")
}

/// Build the memo for a RELEASE action.
pub fn build_release_memo(
    name: &str,
    nonce: u64,
    signature_b64: &str,
    user_pubkey: Option<&str>,
) -> String {
    let base = format!("ZNS:RELEASE:{name}:{nonce}:{signature_b64}");
    match user_pubkey {
        Some(pk) => format!("{base}:{pk}"),
        None => base,
    }
}

// ── UPDATE ───────────────────────────────────────────────────────────────────

/// Bytes to sign for an UPDATE action: `"UPDATE:{name}:{new_ua}:{nonce}"`.
pub fn update_payload(name: &str, new_ua: &str, nonce: u64) -> String {
    format!("UPDATE:{name}:{new_ua}:{nonce}")
}

/// Build the memo for an UPDATE action.
pub fn build_update_memo(
    name: &str,
    new_ua: &str,
    nonce: u64,
    signature_b64: &str,
    user_pubkey: Option<&str>,
) -> String {
    let base = format!("ZNS:UPDATE:{name}:{new_ua}:{nonce}:{signature_b64}");
    match user_pubkey {
        Some(pk) => format!("{base}:{pk}"),
        None => base,
    }
}

// ── BUY ──────────────────────────────────────────────────────────────────────

/// Bytes to sign for a BUY action: `"BUY:{name}:{buyer_ua}"`.
pub fn buy_payload(name: &str, buyer_ua: &str) -> String {
    format!("BUY:{name}:{buyer_ua}")
}

/// Build the memo for a BUY action.
pub fn build_buy_memo(
    name: &str,
    buyer_ua: &str,
    signature_b64: &str,
    user_pubkey: Option<&str>,
) -> String {
    let base = format!("ZNS:BUY:{name}:{buyer_ua}:{signature_b64}");
    match user_pubkey {
        Some(pk) => format!("{base}:{pk}"),
        None => base,
    }
}

// ── SETPRICE ─────────────────────────────────────────────────────────────────

/// Bytes to sign for a SETPRICE action.
///
/// Format: `"SETPRICE:{count}:{p0}:{p1}:...:{pN-1}:{nonce}"`
pub fn setprice_payload(prices: &[u64], nonce: u64) -> String {
    let count = prices.len();
    let joined = prices
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(":");
    format!("SETPRICE:{count}:{joined}:{nonce}")
}

/// Build the memo for a SETPRICE action.
pub fn build_setprice_memo(prices: &[u64], nonce: u64, signature_b64: &str) -> String {
    let count = prices.len();
    let joined = prices
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(":");
    format!("ZNS:SETPRICE:{count}:{joined}:{nonce}:{signature_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_roundtrip() {
        assert_eq!(claim_payload("alice", "utest1xxx"), "CLAIM:alice:utest1xxx");
        assert_eq!(
            build_claim_memo("alice", "utest1xxx", "SIG", None),
            "ZNS:CLAIM:alice:utest1xxx:SIG"
        );
        assert_eq!(
            build_claim_memo("alice", "utest1xxx", "SIG", Some("PK")),
            "ZNS:CLAIM:alice:utest1xxx:SIG:PK"
        );
    }

    #[test]
    fn list_roundtrip() {
        assert_eq!(list_payload("bob", 100_000, 3), "LIST:bob:100000:3");
        assert_eq!(
            build_list_memo("bob", 100_000, 3, "SIG", None),
            "ZNS:LIST:bob:100000:3:SIG"
        );
        assert_eq!(
            build_list_memo("bob", 100_000, 3, "SIG", Some("PK")),
            "ZNS:LIST:bob:100000:3:SIG:PK"
        );
    }

    #[test]
    fn delist_roundtrip() {
        assert_eq!(delist_payload("bob", 4), "DELIST:bob:4");
        assert_eq!(
            build_delist_memo("bob", 4, "SIG", None),
            "ZNS:DELIST:bob:4:SIG"
        );
        assert_eq!(
            build_delist_memo("bob", 4, "SIG", Some("PK")),
            "ZNS:DELIST:bob:4:SIG:PK"
        );
    }

    #[test]
    fn release_roundtrip() {
        assert_eq!(release_payload("bob", 5), "RELEASE:bob:5");
        assert_eq!(
            build_release_memo("bob", 5, "SIG", None),
            "ZNS:RELEASE:bob:5:SIG"
        );
        assert_eq!(
            build_release_memo("bob", 5, "SIG", Some("PK")),
            "ZNS:RELEASE:bob:5:SIG:PK"
        );
    }

    #[test]
    fn update_roundtrip() {
        assert_eq!(
            update_payload("alice", "utest1new", 2),
            "UPDATE:alice:utest1new:2"
        );
        assert_eq!(
            build_update_memo("alice", "utest1new", 2, "SIG", None),
            "ZNS:UPDATE:alice:utest1new:2:SIG"
        );
        assert_eq!(
            build_update_memo("alice", "utest1new", 2, "SIG", Some("PK")),
            "ZNS:UPDATE:alice:utest1new:2:SIG:PK"
        );
    }

    #[test]
    fn buy_roundtrip() {
        assert_eq!(buy_payload("carol", "utest1buy"), "BUY:carol:utest1buy");
        assert_eq!(
            build_buy_memo("carol", "utest1buy", "SIG", None),
            "ZNS:BUY:carol:utest1buy:SIG"
        );
        assert_eq!(
            build_buy_memo("carol", "utest1buy", "SIG", Some("PK")),
            "ZNS:BUY:carol:utest1buy:SIG:PK"
        );
    }

    #[test]
    fn setprice_roundtrip() {
        let prices = [
            600_000_000,
            425_000_000,
            300_000_000,
            150_000_000,
            75_000_000,
        ];
        assert_eq!(
            setprice_payload(&prices, 1),
            "SETPRICE:5:600000000:425000000:300000000:150000000:75000000:1"
        );
        assert_eq!(
            build_setprice_memo(&prices, 1, "SIG"),
            "ZNS:SETPRICE:5:600000000:425000000:300000000:150000000:75000000:1:SIG"
        );
    }
}
