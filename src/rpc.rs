// ZNS JSON-RPC server — read-only API over raw TCP.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zcash_address::ZcashAddress;

use crate::registry::Registry;

pub struct RpcState {
    pub db_path: String,
    pub synced_height: Arc<AtomicU64>,
    pub admin_pubkey: String,
    pub uivk: String,
}

pub async fn serve(addr: String, state: Arc<RpcState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    println!("RPC server listening on {addr}");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let body = match request.find("\r\n\r\n") {
                Some(i) => &request[i + 4..],
                None => return,
            };

            let response = handle_request(body, &state);
            let json = response.to_string();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json.len(),
                json
            );
            let _ = stream.write_all(http.as_bytes()).await;
        });
    }
}

fn handle_request(body: &str, state: &RpcState) -> Value {
    let req: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return jsonrpc_error(Value::Null, -32700, "Parse error"),
    };

    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return jsonrpc_error(id, -32600, "Invalid request"),
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let reg = match Registry::open(&state.db_path) {
        Ok(r) => r,
        Err(_) => return jsonrpc_error(id, -32603, "Internal error"),
    };

    match method {
        "resolve" => handle_resolve(&reg, id, &params),
        "list_for_sale" => handle_list_for_sale(&reg, id),
        "status" => handle_status(&reg, id, state),
        "events" => handle_events(&reg, id, &params),
        _ => jsonrpc_error(id, -32601, "Method not found"),
    }
}

// ── Method handlers ──────────────────────────────────────────────────────────

fn handle_resolve(reg: &Registry, id: Value, params: &Value) -> Value {
    let query = match params.get("query").and_then(|q| q.as_str()) {
        Some(q) => q,
        None => return jsonrpc_error(id, -32602, "Invalid params: missing 'query'"),
    };

    if query.parse::<ZcashAddress>().is_ok() {
        let regs = reg.resolve_by_address(query);
        let results: Vec<Value> = regs
            .iter()
            .map(|r| {
                let listing = reg.get_listing(&r.name);
                json!({
                    "name": r.name,
                    "address": r.address,
                    "txid": r.txid,
                    "height": r.height,
                    "nonce": r.nonce,
                    "signature": r.signature,
                    "listing": listing.map(|l| json!({
                        "name": l.name,
                        "price": l.price,
                        "txid": l.txid,
                        "height": l.height,
                        "signature": l.signature,
                    })),
                })
            })
            .collect();
        jsonrpc_ok(id, json!(results))
    } else {
        let result = match reg.resolve_by_name(query) {
            Some(r) => {
                let listing = reg.get_listing(&r.name);
                json!({
                    "name": r.name,
                    "address": r.address,
                    "txid": r.txid,
                    "height": r.height,
                    "nonce": r.nonce,
                    "signature": r.signature,
                    "listing": listing.map(|l| json!({
                        "name": l.name,
                        "price": l.price,
                        "txid": l.txid,
                        "height": l.height,
                        "signature": l.signature,
                    })),
                })
            }
            None => Value::Null,
        };
        jsonrpc_ok(id, result)
    }
}

fn handle_list_for_sale(reg: &Registry, id: Value) -> Value {
    let listings: Vec<Value> = reg
        .list_for_sale()
        .into_iter()
        .map(|l| {
            json!({
                "name": l.name,
                "price": l.price,
                "txid": l.txid,
                "height": l.height,
                "signature": l.signature,
            })
        })
        .collect();
    jsonrpc_ok(id, json!({ "listings": listings }))
}

fn handle_status(reg: &Registry, id: Value, state: &RpcState) -> Value {
    let pricing = reg.get_pricing().map(|p| {
        json!({
            "nonce": p.nonce,
            "height": p.height,
            "tiers": p.tiers,
        })
    });

    jsonrpc_ok(
        id,
        json!({
            "synced_height": state.synced_height.load(Ordering::Relaxed),
            "admin_pubkey": state.admin_pubkey,
            "uivk": state.uivk,
            "registered": reg.count_registrations(),
            "listed": reg.count_listings(),
            "pricing": pricing,
        }),
    )
}

fn handle_events(reg: &Registry, id: Value, params: &Value) -> Value {
    let name = params.get("name").and_then(|v| v.as_str());
    let actions: Vec<&str> = match params.get("action") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => vec![],
    };
    let since_height = params.get("since_height").and_then(|v| v.as_u64());
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .min(500);
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);

    let page = reg.query_events(name, &actions, since_height, limit, offset);

    let events: Vec<Value> = page
        .events
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id,
                "name": e.name,
                "action": e.action,
                "txid": e.txid,
                "height": e.height,
                "ua": e.ua,
                "price": e.price,
                "nonce": e.nonce,
                "signature": e.signature,
            })
        })
        .collect();

    jsonrpc_ok(id, json!({ "events": events, "total": page.total }))
}

// ── JSON-RPC envelope ────────────────────────────────────────────────────────

fn jsonrpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
