//! Schema types mirroring `ZNS/openrpc.json`.
//!
//! Deserialization targets for the indexer's JSON-RPC responses, plus
//! the one caller-facing input struct ([`EventsFilter`]). Keep this
//! file in sync with `openrpc.json` — any schema drift shows up as
//! deserialization errors in `Client` methods.

use serde::{Deserialize, Serialize};

/// A ZNS name registration as served by the indexer.
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub name: String,
    pub address: String,
    pub txid: String,
    pub height: u64,
    pub nonce: u64,
    pub signature: Option<String>,
    pub last_action: LastAction,
    #[serde(default)]
    pub listing: Option<Listing>,
}

/// Which action wrote the current `signature` on a [`Registration`].
///
/// Determines the pre-image format used for Ed25519 verification. See
/// `ZNS/openrpc.json` and `ZNS/src/memo.rs` for the exact formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum LastAction {
    #[serde(rename = "CLAIM")]
    Claim,
    #[serde(rename = "UPDATE")]
    Update,
    #[serde(rename = "DELIST")]
    Delist,
    #[serde(rename = "BUY")]
    Buy,
}

/// An active marketplace listing for a registered name.
#[derive(Debug, Clone, Deserialize)]
pub struct Listing {
    pub name: String,
    pub price: u64,
    pub nonce: u64,
    pub txid: String,
    pub height: u64,
    pub signature: String,
}

/// Current indexer state.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    pub synced_height: u64,
    pub admin_pubkey: String,
    pub uivk: String,
    pub registered: u64,
    pub listed: u64,
    pub pricing: Option<Pricing>,
}

/// Current pricing configuration.
///
/// `tiers[i]` is the claim cost in zatoshis for a name of length
/// `i + 1`. Names longer than the tier array fall back to the last
/// (cheapest) tier — see [`crate::pricing::claim_cost`].
#[derive(Debug, Clone, Deserialize)]
pub struct Pricing {
    pub nonce: u64,
    pub height: u64,
    pub tiers: Vec<u64>,
}

/// A single ZNS activity event.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub id: u64,
    pub name: String,
    pub action: Action,
    pub txid: String,
    pub height: u64,
    pub ua: Option<String>,
    pub price: Option<u64>,
    pub nonce: Option<u64>,
    pub signature: Option<String>,
}

/// Every action type the indexer tracks.
///
/// Note that [`LastAction`] is a strict subset of this — it only
/// covers the four actions that can be "the most recent signature on a
/// Registration row." The other three (`List`, `Release`, `SetPrice`)
/// live on other tables or are global.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Action {
    #[serde(rename = "CLAIM")]
    Claim,
    #[serde(rename = "LIST")]
    List,
    #[serde(rename = "DELIST")]
    Delist,
    #[serde(rename = "RELEASE")]
    Release,
    #[serde(rename = "UPDATE")]
    Update,
    #[serde(rename = "BUY")]
    Buy,
    #[serde(rename = "SETPRICE")]
    SetPrice,
}

/// Filter parameters for [`crate::Client::events`].
///
/// Every field is optional. Omitted fields are not sent to the
/// indexer, which applies its own defaults (limit = 50, offset = 0).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EventsFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

/// A paginated slice of events.
///
/// `events` holds the page; `total` is the total count across all
/// pages (before `limit`/`offset`), so callers can compute how many
/// pages remain.
#[derive(Debug, Clone, Deserialize)]
pub struct EventsPage {
    pub events: Vec<Event>,
    pub total: u64,
}
