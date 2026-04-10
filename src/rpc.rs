// ZNS JSON-RPC server — jsonrpsee-based API.

use tokio::sync::watch;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use zcash_address::ZcashAddress;

use crate::registry::Registry;

pub struct RpcState {
    pub db_path: String,
    pub synced_height: watch::Receiver<u64>,
    pub admin_pubkey: String,
    pub uivk: String,
    pub address: String,
}

// ── Response types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RegistrationEntry {
    name: String,
    address: String,
    txid: String,
    height: u64,
    nonce: u64,
    signature: Option<String>,
    last_action: String,
    pubkey: Option<String>,
    listing: Option<ListingEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ListingEntry {
    name: String,
    price: u64,
    nonce: u64,
    txid: String,
    height: u64,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ListForSaleResult {
    listings: Vec<ListingEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StatusResult {
    synced_height: u64,
    admin_pubkey: String,
    uivk: String,
    address: String,
    registered: u64,
    listed: u64,
    pricing: Option<PricingEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PricingEntry {
    nonce: u64,
    height: u64,
    tiers: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EventEntry {
    id: u64,
    name: String,
    action: String,
    txid: String,
    height: u64,
    ua: Option<String>,
    price: Option<u64>,
    nonce: Option<u64>,
    signature: Option<String>,
    pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EventsResult {
    events: Vec<EventEntry>,
    total: u64,
}

// ── RPC trait ───────────────────────────────────────────────────────────────

#[rpc(server)]
pub trait ZnsApi {
    #[method(name = "resolve", blocking)]
    fn resolve(&self, query: String) -> RpcResult<Value>;

    #[method(name = "list_for_sale", blocking)]
    fn list_for_sale(&self) -> RpcResult<ListForSaleResult>;

    #[method(name = "status", blocking)]
    fn status(&self) -> RpcResult<StatusResult>;

    #[method(name = "events", blocking)]
    fn events(
        &self,
        name: Option<String>,
        action: Option<String>,
        since_height: Option<u64>,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> RpcResult<EventsResult>;
}

// ── Implementation ──────────────────────────────────────────────────────────

impl ZnsApiServer for RpcState {
    fn resolve(&self, query: String) -> RpcResult<Value> {
        let reg = open_registry(&self.db_path)?;

        if query.parse::<ZcashAddress>().is_ok() {
            let entries: Vec<RegistrationEntry> = reg
                .resolve_by_address(&query)
                .into_iter()
                .map(|r| {
                    let listing = reg.get_listing(&r.name).map(listing_entry);
                    registration_entry(r, listing)
                })
                .collect();
            Ok(serde_json::to_value(entries).unwrap())
        } else {
            let entry = reg.resolve_by_name(&query).map(|r| {
                let listing = reg.get_listing(&r.name).map(listing_entry);
                registration_entry(r, listing)
            });
            Ok(serde_json::to_value(entry).unwrap())
        }
    }

    fn list_for_sale(&self) -> RpcResult<ListForSaleResult> {
        let reg = open_registry(&self.db_path)?;
        let listings = reg.list_for_sale().into_iter().map(listing_entry).collect();
        Ok(ListForSaleResult { listings })
    }

    fn status(&self) -> RpcResult<StatusResult> {
        let reg = open_registry(&self.db_path)?;
        let pricing = reg.get_pricing().map(|p| PricingEntry {
            nonce: p.nonce,
            height: p.height,
            tiers: p.tiers,
        });
        Ok(StatusResult {
            synced_height: *self.synced_height.borrow(),
            admin_pubkey: self.admin_pubkey.clone(),
            uivk: self.uivk.clone(),
            address: self.address.clone(),
            registered: reg.count_registrations(),
            listed: reg.count_listings(),
            pricing,
        })
    }

    fn events(
        &self,
        name: Option<String>,
        action: Option<String>,
        since_height: Option<u64>,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> RpcResult<EventsResult> {
        let reg = open_registry(&self.db_path)?;
        let limit = limit.unwrap_or(50).min(500);
        let offset = offset.unwrap_or(0);
        let actions: Vec<&str> = action.as_deref().into_iter().collect();

        let page = reg.query_events(name.as_deref(), &actions, since_height, limit, offset);

        let events = page
            .events
            .into_iter()
            .map(|e| EventEntry {
                id: e.id,
                name: e.name,
                action: e.action,
                txid: e.txid,
                height: e.height,
                ua: e.ua,
                price: e.price,
                nonce: e.nonce,
                signature: e.signature,
                pubkey: e.pubkey,
            })
            .collect();

        Ok(EventsResult {
            events,
            total: page.total,
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn open_registry(db_path: &str) -> RpcResult<Registry> {
    Registry::open(db_path)
        .map_err(|_| ErrorObjectOwned::owned(-32603, "Internal error", None::<()>))
}

fn registration_entry(
    r: crate::registry::Registration,
    listing: Option<ListingEntry>,
) -> RegistrationEntry {
    RegistrationEntry {
        name: r.name,
        address: r.address,
        txid: r.txid,
        height: r.height,
        nonce: r.nonce,
        signature: r.signature,
        last_action: r.last_action,
        pubkey: r.pubkey,
        listing,
    }
}

fn listing_entry(l: crate::registry::Listing) -> ListingEntry {
    ListingEntry {
        name: l.name,
        price: l.price,
        nonce: l.nonce,
        txid: l.txid,
        height: l.height,
        signature: l.signature,
    }
}

// ── Server ──────────────────────────────────────────────────────────────────

pub async fn serve(addr: String, state: RpcState) {
    let server = match Server::builder().build(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("RPC server failed to bind {addr}: {e}");
            return;
        }
    };
    let handle = server.start(state.into_rpc());
    println!("RPC server listening on {addr}");
    handle.stopped().await;
}
