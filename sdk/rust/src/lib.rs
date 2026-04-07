//! Rust client for the ZNS (Zcash Name System) indexer.
//!
//! Wraps the JSON-RPC API served by the ZNS indexer, parses responses
//! into typed values, and (from M2 onwards) verifies Ed25519 admin
//! signatures client-side so wallets can resolve human-readable names
//! without blindly trusting the indexer.
//!
//! The authoritative RPC schema lives at `ZNS/openrpc.json`. The
//! canonical pre-image format for signature verification lives at
//! `ZNS/src/memo.rs` in the same repository.

mod client;

pub mod memo;
pub mod name;
pub mod pricing;
pub mod types;
pub mod verify;

pub use client::Client;
pub use types::{
    Action, Event, EventsFilter, EventsPage, LastAction, Listing, Pricing, Registration, Status,
};
pub use verify::{AdminPubkey, VerifiedListing, VerifiedRegistration};
