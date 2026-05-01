use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

/// SQLite-backed index of listings and purchases.
pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Listing {
    pub id: i64,
    pub contract_listing_id: Option<i64>,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub winning_purchase_id: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Purchase {
    pub id: i64,
    pub contract_purchase_id: Option<i64>,
    pub listing_id: i64,
    pub buyer_ua: String,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub buyer_signature_b64: Option<String>,
    pub buyer_pubkey_b64: Option<String>,
    pub payout_tx: Vec<u8>,
    pub refund_tx: Vec<u8>,
    pub status: PurchaseStatus,
    pub created_at: DateTime<Utc>,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<i64>,
    pub build_height: Option<i64>,
    pub settlement_txid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurchaseStatus {
    AwaitingPayment,
    PayoutAuthorized,
    Completed,
    Refundable,
    Refunded,
    Expired,
}

impl PurchaseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PurchaseStatus::AwaitingPayment => "awaiting_payment",
            PurchaseStatus::PayoutAuthorized => "payout_authorized",
            PurchaseStatus::Completed => "completed",
            PurchaseStatus::Refundable => "refundable",
            PurchaseStatus::Refunded => "refunded",
            PurchaseStatus::Expired => "expired",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "awaiting_payment" => Ok(PurchaseStatus::AwaitingPayment),
            "payout_authorized" => Ok(PurchaseStatus::PayoutAuthorized),
            "completed" => Ok(PurchaseStatus::Completed),
            "refundable" => Ok(PurchaseStatus::Refundable),
            "refunded" => Ok(PurchaseStatus::Refunded),
            "expired" => Ok(PurchaseStatus::Expired),
            _ => bail!("unknown purchase status: {}", s),
        }
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open SQLite")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS listings (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_listing_id INTEGER,
                name                TEXT NOT NULL,
                seller_ua           TEXT NOT NULL,
                price_zat           INTEGER NOT NULL,
                commission_bps      INTEGER NOT NULL,
                treasury_ua         TEXT NOT NULL,
                winning_purchase_id INTEGER,
                created_at          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_listings_name ON listings(name);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_listings_name_unique ON listings(name);

            CREATE TABLE IF NOT EXISTS purchases (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_purchase_id INTEGER,
                listing_id           INTEGER NOT NULL REFERENCES listings(id),
                buyer_ua             TEXT NOT NULL,
                burner_taddr         TEXT NOT NULL UNIQUE,
                burner_pubkey_hex    TEXT NOT NULL,
                mpc_path             TEXT NOT NULL,
                buyer_signature_b64  TEXT,
                buyer_pubkey_b64     TEXT,
                payout_bundle        BLOB NOT NULL,
                refund_bundle        BLOB NOT NULL,
                status               TEXT NOT NULL,
                created_at           TEXT NOT NULL,
                funding_txid         TEXT,
                funding_vout         INTEGER,
                build_height         INTEGER,
                payout_txid          TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_purchases_status ON purchases(status);
            CREATE INDEX IF NOT EXISTS idx_purchases_burner ON purchases(burner_taddr);
            "#,
        )
        .context("create tables")?;
        ensure_column(&conn, "purchases", "build_height", "INTEGER")?;
        ensure_column(&conn, "purchases", "buyer_signature_b64", "TEXT")?;
        ensure_column(&conn, "purchases", "buyer_pubkey_b64", "TEXT")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|e| anyhow::anyhow!("poison: {e}"))
    }

    pub fn get_listing_by_id(&self, id: i64) -> Result<Option<Listing>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, contract_listing_id, name, seller_ua, price_zat, commission_bps, treasury_ua, winning_purchase_id, created_at
             FROM listings WHERE id = ?1",
            params![id],
            |row| self.row_to_listing(row),
        )
        .optional()
        .context("get listing")
    }

    pub fn upsert_listing(
        &self,
        contract_listing_id: i64,
        name: &str,
        seller_ua: &str,
        price_zat: u64,
        commission_bps: u64,
        treasury_ua: &str,
        winning_purchase_id: Option<i64>,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO listings (contract_listing_id, name, seller_ua, price_zat, commission_bps, treasury_ua, winning_purchase_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(name) DO UPDATE SET
                 contract_listing_id = excluded.contract_listing_id,
                 seller_ua = excluded.seller_ua,
                 price_zat = excluded.price_zat,
                 commission_bps = excluded.commission_bps,
                 treasury_ua = excluded.treasury_ua,
                 winning_purchase_id = excluded.winning_purchase_id",
            params![
                contract_listing_id,
                name,
                seller_ua,
                price_zat as i64,
                commission_bps as i64,
                treasury_ua,
                winning_purchase_id,
                now
            ],
        )
        .context("upsert listing")?;
        conn.query_row(
            "SELECT id FROM listings WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
        .context("get upserted listing id")
    }

    pub fn insert_purchase(
        &self,
        listing_id: i64,
        buyer_ua: &str,
        burner_taddr: &str,
        burner_pubkey_hex: &str,
        mpc_path: &str,
        buyer_signature_b64: Option<&str>,
        buyer_pubkey_b64: Option<&str>,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO purchases (listing_id, buyer_ua, burner_taddr, burner_pubkey_hex, mpc_path, buyer_signature_b64, buyer_pubkey_b64, payout_bundle, refund_bundle, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                listing_id,
                buyer_ua,
                burner_taddr,
                burner_pubkey_hex,
                mpc_path,
                buyer_signature_b64,
                buyer_pubkey_b64,
                Vec::<u8>::new(),
                Vec::<u8>::new(),
                PurchaseStatus::AwaitingPayment.as_str(),
                now,
            ],
        )
        .context("insert purchase")?;
        Ok(conn.last_insert_rowid())
    }

    pub fn set_contract_purchase_id(&self, local_id: i64, contract_id: i64) -> Result<()> {
        self.lock()?.execute(
            "UPDATE purchases SET contract_purchase_id = ?1 WHERE id = ?2",
            params![contract_id, local_id],
        )?;
        Ok(())
    }

    pub fn list_work_queue(&self) -> Result<Vec<Purchase>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT
                id, contract_purchase_id, listing_id, buyer_ua, burner_taddr,
                burner_pubkey_hex, mpc_path, buyer_signature_b64, buyer_pubkey_b64,
                payout_bundle, refund_bundle, status, created_at,
                funding_txid, funding_vout, build_height, payout_txid
             FROM purchases
             WHERE status IN ('awaiting_payment','payout_authorized','refundable')
                OR (status IN ('completed','refunded') AND payout_txid IS NULL)
             ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| self.row_to_purchase(row))?;
        rows.collect::<Result<_, _>>().context("list work queue")
    }

    pub fn update_purchase_status(&self, id: i64, status: PurchaseStatus) -> Result<()> {
        self.lock()?.execute(
            "UPDATE purchases SET status = ?1 WHERE id = ?2",
            params![status.as_str(), id],
        )?;
        Ok(())
    }

    pub fn store_funding(
        &self,
        id: i64,
        funding_txid: &str,
        funding_vout: u32,
        build_height: u32,
        payout_tx: &[u8],
        refund_tx: &[u8],
        status: PurchaseStatus,
    ) -> Result<()> {
        self.lock()?.execute(
            "UPDATE purchases
             SET funding_txid = ?1,
                 funding_vout = ?2,
                 build_height = ?3,
                 payout_bundle = ?4,
                 refund_bundle = ?5,
                 status = ?6
             WHERE id = ?7",
            params![
                funding_txid,
                funding_vout as i64,
                build_height as i64,
                payout_tx,
                refund_tx,
                status.as_str(),
                id
            ],
        )?;
        Ok(())
    }

    pub fn set_settlement_txid(&self, id: i64, txid: &str, status: PurchaseStatus) -> Result<()> {
        self.lock()?.execute(
            "UPDATE purchases SET payout_txid = ?1, status = ?2 WHERE id = ?3",
            params![txid, status.as_str(), id],
        )?;
        Ok(())
    }

    fn row_to_listing(&self, row: &rusqlite::Row) -> rusqlite::Result<Listing> {
        let created_at_str: String = row.get(8)?;
        let created_at = created_at_str.parse::<DateTime<Utc>>().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;
        Ok(Listing {
            id: row.get(0)?,
            contract_listing_id: row.get(1)?,
            name: row.get(2)?,
            seller_ua: row.get(3)?,
            price_zat: row.get::<_, i64>(4)? as u64,
            commission_bps: row.get::<_, i64>(5)? as u64,
            treasury_ua: row.get(6)?,
            winning_purchase_id: row.get(7)?,
            created_at,
        })
    }

    fn row_to_purchase(&self, row: &rusqlite::Row) -> rusqlite::Result<Purchase> {
        let status_str: String = row.get(11)?;
        let created_at_str: String = row.get(12)?;

        let status = PurchaseStatus::from_str(&status_str).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                11,
                rusqlite::types::Type::Text,
                e.to_string().into(),
            )
        })?;
        let created_at = created_at_str.parse::<DateTime<Utc>>().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(12, rusqlite::types::Type::Text, Box::new(e))
        })?;

        Ok(Purchase {
            id: row.get(0)?,
            contract_purchase_id: row.get(1)?,
            listing_id: row.get(2)?,
            buyer_ua: row.get(3)?,
            burner_taddr: row.get(4)?,
            burner_pubkey_hex: row.get(5)?,
            mpc_path: row.get(6)?,
            buyer_signature_b64: row.get(7)?,
            buyer_pubkey_b64: row.get(8)?,
            payout_tx: row.get(9)?,
            refund_tx: row.get(10)?,
            status,
            created_at,
            funding_txid: row.get(13)?,
            funding_vout: row.get(14)?,
            build_height: row.get(15)?,
            settlement_txid: row.get(16)?,
        })
    }
}

fn ensure_column(conn: &Connection, table: &str, column: &str, ty: &str) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|existing| existing == column) {
        let alter = format!("ALTER TABLE {table} ADD COLUMN {column} {ty}");
        conn.execute(&alter, []).context("add column")?;
    }
    Ok(())
}
