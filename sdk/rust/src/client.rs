//! Thin JSON-RPC client for the ZNS indexer.
//!
//! Wraps every indexer method as a typed async function. Holds a
//! `reqwest::Client` and an endpoint `Url`; posts one request per
//! call, deserializes the response, returns a typed value. No
//! retries, no caching, no transport abstraction — if you need any of
//! those, configure the `reqwest::Client` before passing it to
//! [`Client::with_http_client`].

use crate::types::{EventsFilter, EventsPage, Listing, Registration, Status};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

/// Thin JSON-RPC client for the ZNS indexer.
///
/// Construct one per endpoint. `Client` is cheap to clone — both
/// fields are reference-counted internally by `reqwest`.
#[derive(Debug, Clone)]
pub struct Client {
    endpoint: Url,
    http: reqwest::Client,
}

impl Client {
    /// Build a client with a fresh default `reqwest::Client`.
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            http: reqwest::Client::new(),
        }
    }

    /// Build a client reusing a caller-supplied `reqwest::Client`.
    ///
    /// Use this to inject a pre-configured HTTP client — for example,
    /// one routed through a SOCKS proxy, or Arti's `reqwest::Client`
    /// for Tor-routed requests.
    pub fn with_http_client(endpoint: Url, http: reqwest::Client) -> Self {
        Self { endpoint, http }
    }

    /// Resolve a ZNS name to its current registration.
    ///
    /// Returns `Ok(None)` if the name is not registered. Does not
    /// accept addresses — use [`Self::resolve_address`] for those.
    pub async fn resolve(&self, name: &str) -> anyhow::Result<Option<Registration>> {
        self.call("resolve", json!([name])).await
    }

    /// List every registration currently bound to the given Zcash
    /// unified address.
    ///
    /// A single address may own multiple names; returns an empty
    /// vector if the address owns none.
    pub async fn resolve_address(&self, address: &str) -> anyhow::Result<Vec<Registration>> {
        self.call("resolve", json!([address])).await
    }

    /// Returns `true` if the name is not currently registered.
    ///
    /// Convenience over [`Self::resolve`] — one RPC round-trip.
    pub async fn is_available(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self.resolve(name).await?.is_none())
    }

    /// Returns every name currently listed for sale, newest first.
    pub async fn list_for_sale(&self) -> anyhow::Result<Vec<Listing>> {
        #[derive(Deserialize)]
        struct ListForSaleResponse {
            listings: Vec<Listing>,
        }
        let r: ListForSaleResponse = self.call("list_for_sale", json!([])).await?;
        Ok(r.listings)
    }

    /// Indexer state: synced height, admin pubkey, name/listing counts,
    /// and current pricing.
    pub async fn status(&self) -> anyhow::Result<Status> {
        self.call("status", json!([])).await
    }

    /// Query the activity log with optional filters.
    ///
    /// Results are ordered by block height descending (newest first).
    /// See [`EventsFilter`] for the available filter fields.
    pub async fn events(&self, filter: EventsFilter) -> anyhow::Result<EventsPage> {
        let params = serde_json::to_value(&filter)?;
        self.call("events", params).await
    }

    /// Send one JSON-RPC request and deserialize its `result` field.
    async fn call<T>(&self, method: &str, params: Value) -> anyhow::Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });

        let resp: JsonRpcResponse<T> = self
            .http
            .post(self.endpoint.as_str())
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            anyhow::bail!("JSON-RPC error {}: {}", err.code, err.message);
        }
        resp.result
            .ok_or_else(|| anyhow::anyhow!("JSON-RPC response had neither result nor error"))
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}
