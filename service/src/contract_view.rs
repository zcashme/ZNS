//! Narrow decoders for the only contract fields the service consumes.
//!
//! The contract's full `Listing` has 17 fields. The service only reads 4 of
//! them — `id`, `funded`, `listing_nonce`, and (transitively, via the worker)
//! the existence of a payout signature. Decoding into a narrow struct means
//! contract changes that don't touch these four fields are invisible to us.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ContractListingMeta {
    pub id: u64,
    pub listing_nonce: u64,
    pub funded: bool,
}
