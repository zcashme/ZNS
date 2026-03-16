# ZNS gRPC Endpoint (removed, to be re-added)

## Overview

The indexer previously served a gRPC endpoint for ZNS record lookups. This documents the removed code for re-integration later.

## Proto (proto/zns.proto)

```proto
service ZnsService {
  rpc GetZnsRecord (ZnsQuery) returns (ZnsRecord);
}
```

## Config

```rust
const GRPC_ADDR: &str = "[::1]:50052";
```

## DbPool

Thread-safe wrapper that opens a `rusqlite::Connection` per query on a blocking thread (since `Connection` is `!Send`).

```rust
#[derive(Clone)]
struct DbPool {
    path: Arc<str>,
}

impl DbPool {
    fn new(path: &str) -> Self {
        Self { path: Arc::from(path) }
    }

    async fn query<F, T>(&self, f: F) -> Result<T, Status>
    where
        F: FnOnce(&Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&*path)
                .map_err(|e| Status::internal(format!("db open error: {e}")))?;
            Ok(f(&conn))
        })
        .await
        .map_err(|e| Status::internal(format!("task join error: {e}")))?
    }
}
```

## ZnsServer + Service Impl

```rust
struct ZnsServer {
    db: DbPool,
}

#[tonic::async_trait]
impl zns_proto::zns_service_server::ZnsService for ZnsServer {
    async fn get_zns_record(
        &self,
        request: Request<zns_proto::ZnsQuery>,
    ) -> Result<Response<zns_proto::ZnsRecord>, Status> {
        let inner = request.into_inner();
        let record_type = inner.record_type();
        let query = inner.query.ok_or_else(|| {
            Status::invalid_argument("query must contain either name or address")
        })?;

        // Resolve input to a name
        let name = match query {
            zns_proto::zns_query::Query::Name(n) => {
                n.trim_end_matches(".zec")
                    .trim_end_matches(".zcash")
                    .to_lowercase()
            }
            zns_proto::zns_query::Query::Address(addr) => {
                let found = self.db.query(move |db| resolve_name_by_address(db, &addr)).await?;
                found.ok_or_else(|| Status::not_found("no registration found for address"))?
            }
        };

        // Fetch what the client asked for
        let record = self.db.query(move |db| {
            use zns_proto::RecordType;
            let mut rec = zns_proto::ZnsRecord {
                name: name.clone(),
                registration: None,
                listing: None,
                bids: vec![],
            };

            match record_type {
                RecordType::Registration => {
                    rec.registration = get_registration(db, &name);
                }
                RecordType::Listing => {
                    rec.listing = get_listing(db, &name);
                }
                RecordType::Bids => {
                    rec.bids = get_bids(db, &name);
                }
                RecordType::All => {
                    rec.registration = get_registration(db, &name);
                    rec.listing = get_listing(db, &name);
                    rec.bids = get_bids(db, &name);
                }
            }

            rec
        }).await?;

        Ok(Response::new(record))
    }
}
```

## DB query helpers used by gRPC

```rust
fn resolve_name_by_address(db: &Connection, address: &str) -> Option<String> {
    db.query_row(
        "SELECT name FROM registrations WHERE ua = ?1",
        rusqlite::params![address],
        |row| row.get(0),
    )
    .ok()
}

fn get_registration(db: &Connection, name: &str) -> Option<zns_proto::Registration> {
    db.query_row(
        "SELECT ua, proof, txid, height FROM registrations WHERE name = ?1",
        rusqlite::params![name],
        |row| Ok(zns_proto::Registration {
            address: row.get(0)?,
            proof: row.get(1)?,
            txid: row.get(2)?,
            height: row.get::<_, i64>(3)? as u64,
        }),
    )
    .ok()
}

fn get_listing(db: &Connection, name: &str) -> Option<zns_proto::Listing> {
    db.query_row(
        "SELECT min_price, buy_now, expiry, proof, txid, height FROM listings WHERE name = ?1",
        rusqlite::params![name],
        |row| Ok(zns_proto::Listing {
            min_price: row.get::<_, i64>(0)? as u64,
            buy_now: row.get::<_, i64>(1)? as u64,
            expiry: row.get::<_, i64>(2)? as u64,
            proof: row.get(3)?,
            txid: row.get(4)?,
            height: row.get::<_, i64>(5)? as u64,
        }),
    )
    .ok()
}

fn get_bids(db: &Connection, name: &str) -> Vec<zns_proto::Bid> {
    let mut stmt = db.prepare(
        "SELECT bid_number, ua, amount, proof, txid, height, refunded FROM bids WHERE name = ?1 ORDER BY bid_number"
    ).unwrap();
    stmt.query_map(rusqlite::params![name], |row| {
        Ok(zns_proto::Bid {
            bid_number: row.get::<_, i64>(0)? as u64,
            address: row.get(1)?,
            amount: row.get::<_, i64>(2)? as u64,
            proof: row.get(3)?,
            txid: row.get(4)?,
            height: row.get::<_, i64>(5)? as u64,
            refunded: row.get::<_, i64>(6)? != 0,
        })
    }).unwrap().filter_map(|r| r.ok()).collect()
}
```

## main() gRPC spawn

```rust
// gRPC server opens connections on-demand via DbPool (spawn_blocking)
let grpc_addr = GRPC_ADDR.parse()?;
let zns_service = ZnsServer { db: DbPool::new(DB_PATH) };
tokio::spawn(async move {
    println!("gRPC server listening on {GRPC_ADDR}");
    tonic::transport::Server::builder()
        .add_service(zns_proto::zns_service_server::ZnsServiceServer::new(zns_service))
        .serve(grpc_addr)
        .await
        .expect("gRPC server failed");
});
```

## Imports needed

```rust
use tonic::{Request, Response, Status};
```
