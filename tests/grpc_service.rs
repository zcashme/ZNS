use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tokio::net::TcpListener;
use tonic::transport::Server;

mod zns_proto {
    tonic::include_proto!("zns.v1");
}

use zns_proto::zns_query::Query;
use zns_proto::zns_service_client::ZnsServiceClient;
use zns_proto::ZnsQuery;

// We can't import ZnsServer/ZnsServiceServer from the binary crate directly in
// integration tests, so we re-include the service module via the proto and build
// a thin wrapper. Instead, we use a helper that mirrors the service setup.

// Include the service implementation from the main crate by re-declaring the
// server types from generated code.
use zns_proto::zns_service_server::{ZnsService, ZnsServiceServer};

struct ZnsServer {
    db: Arc<Mutex<Connection>>,
}

impl ZnsServer {
    fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl ZnsService for ZnsServer {
    async fn get_zns_record(
        &self,
        request: tonic::Request<ZnsQuery>,
    ) -> Result<tonic::Response<zns_proto::ZnsRecord>, tonic::Status> {
        let query = request
            .into_inner()
            .query
            .ok_or_else(|| tonic::Status::invalid_argument("query must contain a name or address"))?;

        let db = self.db.lock().map_err(|e| {
            tonic::Status::internal(format!("database lock poisoned: {e}"))
        })?;

        let (sql, param) = match &query {
            Query::Name(name) => {
                if name.is_empty() {
                    return Err(tonic::Status::invalid_argument("name must not be empty"));
                }
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
                    return Err(tonic::Status::invalid_argument("address must not be empty"));
                }
                (
                    "SELECT name, ua FROM registrations WHERE ua = ?1",
                    addr.clone(),
                )
            }
        };

        db.query_row(sql, rusqlite::params![param], |row| {
            Ok(zns_proto::ZnsRecord {
                name: row.get(0)?,
                address: row.get(1)?,
            })
        })
        .map(tonic::Response::new)
        .map_err(|_| tonic::Status::not_found("no matching registration found"))
    }
}

fn create_test_db() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL UNIQUE,
            txid    BLOB NOT NULL,
            height  INTEGER NOT NULL
        );",
    )
    .unwrap();
    Arc::new(Mutex::new(conn))
}

async fn start_server(db: Arc<Mutex<Connection>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(ZnsServiceServer::new(ZnsServer::new(db)))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    url
}

#[tokio::test]
async fn test_not_found_on_empty_db() {
    let db = create_test_db();
    let url = start_server(db).await;

    let mut client = ZnsServiceClient::connect(url).await.unwrap();
    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Name("alice".into())),
        })
        .await;

    let err = resp.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_forward_lookup() {
    let db = create_test_db();
    db.lock().unwrap().execute(
        "INSERT INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params!["alice", "u1testaddr", b"txid123", 100],
    ).unwrap();

    let url = start_server(db).await;
    let mut client = ZnsServiceClient::connect(url).await.unwrap();

    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Name("alice".into())),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.name, "alice");
    assert_eq!(resp.address, "u1testaddr");
}

#[tokio::test]
async fn test_forward_lookup_with_suffix() {
    let db = create_test_db();
    db.lock().unwrap().execute(
        "INSERT INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params!["bob", "u1bobaddr", b"txid456", 200],
    ).unwrap();

    let url = start_server(db).await;
    let mut client = ZnsServiceClient::connect(url).await.unwrap();

    // .zec suffix
    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Name("bob.zec".into())),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.name, "bob");

    // .zcash suffix
    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Name("bob.zcash".into())),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.name, "bob");
}

#[tokio::test]
async fn test_reverse_lookup() {
    let db = create_test_db();
    db.lock().unwrap().execute(
        "INSERT INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params!["charlie", "u1charlieaddr", b"txid789", 300],
    ).unwrap();

    let url = start_server(db).await;
    let mut client = ZnsServiceClient::connect(url).await.unwrap();

    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Address("u1charlieaddr".into())),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.name, "charlie");
    assert_eq!(resp.address, "u1charlieaddr");
}

#[tokio::test]
async fn test_empty_query() {
    let db = create_test_db();
    let url = start_server(db).await;

    let mut client = ZnsServiceClient::connect(url).await.unwrap();

    // No query field set
    let resp = client
        .get_zns_record(ZnsQuery { query: None })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::InvalidArgument);

    // Empty name
    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Name("".into())),
        })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::InvalidArgument);

    // Empty address
    let resp = client
        .get_zns_record(ZnsQuery {
            query: Some(Query::Address("".into())),
        })
        .await;
    assert_eq!(resp.unwrap_err().code(), tonic::Code::InvalidArgument);
}
