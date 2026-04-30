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
pub struct Listing {
    pub id: i64,
    pub contract_listing_id: Option<i64>,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub status: ListingStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListingStatus {
    Open,
    Sold,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct Purchase {
    pub id: i64,
    pub contract_purchase_id: Option<i64>,
    pub listing_id: i64,
    pub buyer_ua: String,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub payout_bundle: Vec<u8>,
    pub refund_bundle: Vec<u8>,
    pub status: PurchaseStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<i64>,
    pub sighash: Option<String>,
    pub payout_txid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurchaseStatus {
    Draft, // local only, not yet on chain
    AwaitingPayment,
    PayoutAuthorized,
    Completed,
    Refundable,
    Refunded,
    Expired,
}

impl PurchaseStatus {
    fn as_str(&self) -> &'static str {
        match self {
            PurchaseStatus::Draft => "draft",
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
            "draft" => Ok(PurchaseStatus::Draft),
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

impl ListingStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ListingStatus::Open => "open",
            ListingStatus::Sold => "sold",
            ListingStatus::Cancelled => "cancelled",
        }
    }
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(ListingStatus::Open),
            "sold" => Ok(ListingStatus::Sold),
            "cancelled" => Ok(ListingStatus::Cancelled),
            _ => bail!("unknown listing status: {}", s),
        }
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open SQLite")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS listings (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_listing_id INTEGER,
                name              TEXT NOT NULL,
                seller_ua         TEXT NOT NULL,
                price_zat         INTEGER NOT NULL,
                commission_bps    INTEGER NOT NULL,
                treasury_ua       TEXT NOT NULL,
                status            TEXT NOT NULL,
                created_at        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_listings_name ON listings(name);
            CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);

            CREATE TABLE IF NOT EXISTS purchases (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_purchase_id INTEGER,
                listing_id          INTEGER NOT NULL REFERENCES listings(id),
                buyer_ua            TEXT NOT NULL,
                burner_taddr        TEXT NOT NULL UNIQUE,
                burner_pubkey_hex   TEXT NOT NULL,
                mpc_path            TEXT NOT NULL,
                payout_bundle       BLOB NOT NULL,
                refund_bundle       BLOB NOT NULL,
                status              TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                expires_at          TEXT NOT NULL,
                funding_txid        TEXT,
                funding_vout        INTEGER,
                sighash             TEXT,
                payout_txid        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_purchases_status ON purchases(status);
            CREATE INDEX IF NOT EXISTS idx_purchases_burner ON purchases(burner_taddr);
            "#,
        )
        .context("create tables")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|e| anyhow::anyhow!("poison: {e}"))
    }

    pub fn insert_listing(
        &self,
        name: &str,
        seller_ua: &str,
        price_zat: u64,
        commission_bps: u64,
        treasury_ua: &str,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO listings (name, seller_ua, price_zat, commission_bps, treasury_ua, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![name, seller_ua, price_zat as i64, commission_bps as i64, treasury_ua, ListingStatus::Open.as_str(), now],
        ).context("insert listing")?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_listing_by_id(&self, id: i64) -> Result<Option<Listing>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, contract_listing_id, name, seller_ua, price_zat, commission_bps, treasury_ua, status, created_at
             FROM listings WHERE id = ?1",
            params![id],
            |row| self.row_to_listing(row),
        )
        .optional()
        .context("get listing")
    }

    pub fn list_open_listings(&self) -> Result<Vec<Listing>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, contract_listing_id, name, seller_ua, price_zat, commission_bps, treasury_ua, status, created_at
             FROM listings WHERE status = 'open' ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| self.row_to_listing(row))?;
        rows.collect::<Result<_, _>>().context("list open listings")
    }

    pub fn insert_purchase(
        &self,
        listing_id: i64,
        buyer_ua: &str,
        burner_taddr: &str,
        burner_pubkey_hex: &str,
        mpc_path: &str,
        payout_bundle: &[u8],
        refund_bundle: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let exp = expires_at.to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO purchases (listing_id, buyer_ua, burner_taddr, burner_pubkey_hex, mpc_path, payout_bundle, refund_bundle, status, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![listing_id, buyer_ua, burner_taddr, burner_pubkey_hex, mpc_path, payout_bundle, refund_bundle, PurchaseStatus::Draft.as_str(), now, exp],
        ).context("insert purchase")?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_purchase_by_id(&self, id: i64) -> Result<Option<Purchase>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, contract_purchase_id, listing_id, buyer_ua, burner_taddr, burner_pubkey_hex, mpc_path,
                    payout_bundle, refund_bundle, status, created_at, expires_at,
                    funding_txid, funding_vout, sighash, payout_txid
             FROM purchases WHERE id = ?1",
            params![id],
            |row| self.row_to_purchase(row),
        )
        .optional()
        .context("get purchase")
    }

    pub fn list_active_purchases(&self) -> Result<Vec<Purchase>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, contract_purchase_id, listing_id, buyer_ua, burner_taddr, burner_pubkey_hex, mpc_path,
                    payout_bundle, refund_bundle, status, created_at, expires_at,
                    funding_txid, funding_vout, sighash, payout_txid
             FROM purchases
             WHERE status IN ('draft','awaiting_payment','payout_authorized','refundable')
             ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| self.row_to_purchase(row))?;
        rows.collect::<Result<_, _>>().context("list active purchases")
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    fn row_to_listing(&self,
        row: &rusqlite::Row,
    ) -> rusqlite::Result<Listing> {
        let status_str: String = row.get(7)?;
        let created_at_str: String = row.get(8)?;
        let status = ListingStatus::from_str(&status_str)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, e.to_string().into()))?;
        let created_at = created_at_str.parse::<DateTime<Utc>>()
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e)))?;
        Ok(Listing {
            id: row.get(0)?,
            contract_listing_id: row.get(1)?,
            name: row.get(2)?,
            seller_ua: row.get(3)?,
            price_zat: row.get::<_, i64>(4)? as u64,
            commission_bps: row.get::<_, i64>(5)? as u64,
            treasury_ua: row.get(6)?,
            status,
            created_at,
        })
    }

    fn row_to_purchase(
        &self,
        row: &rusqlite::Row,
    ) -> rusqlite::Result<Purchase> {
        let status_str: String = row.get(9)?;
        let created_at_str: String = row.get(10)?;
        let expires_at_str: String = row.get(11)?;

        let status = PurchaseStatus::from_str(&status_str)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, e.to_string().into()))?;
        let created_at = created_at_str.parse::<DateTime<Utc>>()
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e)))?;
        let expires_at = expires_at_str.parse::<DateTime<Utc>>()
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e)))?;

        Ok(Purchase {
            id: row.get(0)?,
            contract_purchase_id: row.get(1)?,
            listing_id: row.get(2)?,
            buyer_ua: row.get(3)?,
            burner_taddr: row.get(4)?,
            burner_pubkey_hex: row.get(5)?,
            mpc_path: row.get(6)?,
            payout_bundle: row.get(7)?,
            refund_bundle: row.get(8)?,
            status,
            created_at,
            expires_at,
            funding_txid: row.get(12)?,
            funding_vout: row.get(13)?,
            sighash: row.get(14)?,
            payout_txid: row.get(15)?,
        })
    }
}
