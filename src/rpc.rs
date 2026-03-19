// ZNS JSON-RPC server — read-only API over raw TCP.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zcash_address::ZcashAddress;

pub struct RpcState {
    pub db_path: String,
    pub synced_height: Arc<AtomicU64>,
    pub admin_pubkey: String,
    pub ufvk: String,
}

pub async fn serve(addr: &str, state: Arc<RpcState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
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

    let db = match Connection::open(&state.db_path) {
        Ok(db) => db,
        Err(_) => return jsonrpc_error(id, -32603, "Internal error"),
    };

    match method {
        "resolve" => handle_resolve(&db, id, &params),
        "list_for_sale" => handle_list_for_sale(&db, id),
        "status" => handle_status(&db, id, state),
        _ => jsonrpc_error(id, -32601, "Method not found"),
    }
}

// ── Method handlers ──────────────────────────────────────────────────────────

fn handle_resolve(db: &Connection, id: Value, params: &Value) -> Value {
    let query = match params.get("query").and_then(|q| q.as_str()) {
        Some(q) => q,
        None => return jsonrpc_error(id, -32602, "Invalid params: missing 'query'"),
    };

    let registration = if query.parse::<ZcashAddress>().is_ok() {
        resolve_by_address(db, query)
    } else {
        resolve_by_name(db, query)
    };

    let result = match registration {
        Some(reg) => {
            let listing = get_listing(db, &reg.name);
            json!({
                "name": reg.name,
                "address": reg.address,
                "txid": reg.txid,
                "height": reg.height,
                "nonce": reg.nonce,
                "signature": reg.signature,
                "listing": listing,
            })
        }
        None => Value::Null,
    };

    jsonrpc_ok(id, result)
}

fn handle_list_for_sale(db: &Connection, id: Value) -> Value {
    let listings = list_for_sale(db);
    jsonrpc_ok(id, json!({ "listings": listings }))
}

fn handle_status(db: &Connection, id: Value, state: &RpcState) -> Value {
    jsonrpc_ok(
        id,
        json!({
            "synced_height": state.synced_height.load(Ordering::Relaxed),
            "admin_pubkey": state.admin_pubkey,
            "ufvk": state.ufvk,
            "registered": count_rows(db, "registrations"),
            "listed": count_rows(db, "listings"),
        }),
    )
}

// ── JSON-RPC envelope ────────────────────────────────────────────────────────

fn jsonrpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

// ── DB reads ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Registration {
    name: String,
    address: String,
    txid: String,
    height: u64,
    nonce: u64,
    signature: Option<String>,
}

#[derive(Serialize)]
struct Listing {
    name: String,
    price: u64,
    txid: String,
    height: u64,
    signature: String,
}

fn resolve_by_name(db: &Connection, name: &str) -> Option<Registration> {
    db.query_row(
        "SELECT name, ua, txid, height, nonce, signature FROM registrations WHERE name = ?1",
        [name],
        |row| {
            Ok(Registration {
                name: row.get(0)?,
                address: row.get(1)?,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                nonce: row.get::<_, i64>(4)? as u64,
                signature: row.get(5)?,
            })
        },
    )
    .ok()
}

fn resolve_by_address(db: &Connection, address: &str) -> Option<Registration> {
    db.query_row(
        "SELECT name, ua, txid, height, nonce, signature FROM registrations WHERE ua = ?1",
        [address],
        |row| {
            Ok(Registration {
                name: row.get(0)?,
                address: row.get(1)?,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                nonce: row.get::<_, i64>(4)? as u64,
                signature: row.get(5)?,
            })
        },
    )
    .ok()
}

fn get_listing(db: &Connection, name: &str) -> Option<Listing> {
    db.query_row(
        "SELECT name, price, txid, height, signature FROM listings WHERE name = ?1",
        [name],
        |row| {
            Ok(Listing {
                name: row.get(0)?,
                price: row.get::<_, i64>(1)? as u64,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                signature: row.get(4)?,
            })
        },
    )
    .ok()
}

fn list_for_sale(db: &Connection) -> Vec<Listing> {
    let mut stmt = db
        .prepare(
            "SELECT l.name, l.price, l.txid, l.height, l.signature
         FROM listings l
         ORDER BY l.height DESC",
        )
        .unwrap();
    stmt.query_map([], |row| {
        Ok(Listing {
            name: row.get(0)?,
            price: row.get::<_, i64>(1)? as u64,
            txid: row.get(2)?,
            height: row.get::<_, i64>(3)? as u64,
            signature: row.get(4)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

fn count_rows(db: &Connection, table: &str) -> u64 {
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        Ok(row.get::<_, i64>(0)? as u64)
    })
    .unwrap_or(0)
}
