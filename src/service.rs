use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tonic::{Request, Response, Status};

pub mod zns_proto {
    tonic::include_proto!("zns.v1");
}

use zns_proto::zns_service_server::ZnsService;
use zns_proto::{ZnsQuery, ZnsRecord};
use zns_proto::zns_query::Query;

pub use zns_proto::zns_service_server::ZnsServiceServer;

pub struct ZnsServer {
    db: Arc<Mutex<Connection>>,
}

impl ZnsServer {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl ZnsService for ZnsServer {
    async fn get_zns_record(
        &self,
        request: Request<ZnsQuery>,
    ) -> Result<Response<ZnsRecord>, Status> {
        let query = request
            .into_inner()
            .query
            .ok_or_else(|| Status::invalid_argument("query must contain a name or address"))?;

        let db = self.db.lock().map_err(|e| {
            Status::internal(format!("database lock poisoned: {e}"))
        })?;

        let (sql, param) = match &query {
            Query::Name(name) => {
                if name.is_empty() {
                    return Err(Status::invalid_argument("name must not be empty"));
                }
                // Strip optional .zec / .zcash suffix
                let stripped = name
                    .strip_suffix(".zec")
                    .or_else(|| name.strip_suffix(".zcash"))
                    .unwrap_or(name);
                (
                    "SELECT name, ua FROM registrations WHERE name = ?1",
                    stripped.to_string(),
                )
            }
            Query::Address(addr) => {
                if addr.is_empty() {
                    return Err(Status::invalid_argument("address must not be empty"));
                }
                (
                    "SELECT name, ua FROM registrations WHERE ua = ?1",
                    addr.clone(),
                )
            }
        };

        db.query_row(sql, rusqlite::params![param], |row| {
            Ok(ZnsRecord {
                name: row.get(0)?,
                address: row.get(1)?,
            })
        })
        .map(Response::new)
        .map_err(|_| Status::not_found("no matching registration found"))
    }
}
