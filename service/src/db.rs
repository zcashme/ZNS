use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

/// SQLite-backed index of listings (mirrored from the NEAR contract) and
/// buyer registrations (relayer-only state, never on-chain).
pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Listing {
    pub id: i64,
    pub contract_listing_id: i64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub funded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BuyerRegistration {
    pub id: i64,
    pub listing_id: i64,
    pub buyer_ua: String,
    pub buyer_signature_b64: String,
    pub buyer_pubkey_b64: String,
    pub admin_signature_b64: String,
    /// True if the buyer supplied their own signature (sovereign override);
    /// false if the relayer signed on their behalf with the admin key.
    pub is_sovereign: bool,
    pub status: RegistrationStatus,
    pub created_at: DateTime<Utc>,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<i64>,
    pub build_height: Option<i64>,
    pub payout_txid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationStatus {
    /// Buyer registered; waiting for them to send Zcash to the burner t-addr.
    AwaitingPayment,
    /// Funding UTXO observed; submit_funding accepted on chain. Awaiting MPC payout.
    Submitted,
    /// Payout broadcast.
    Completed,
}

impl RegistrationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistrationStatus::AwaitingPayment => "awaiting_payment",
            RegistrationStatus::Submitted => "submitted",
            RegistrationStatus::Completed => "completed",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "awaiting_payment" => Ok(RegistrationStatus::AwaitingPayment),
            "submitted" => Ok(RegistrationStatus::Submitted),
            "completed" => Ok(RegistrationStatus::Completed),
            _ => bail!("unknown registration status: {}", s),
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
                contract_listing_id INTEGER NOT NULL UNIQUE,
                name                TEXT NOT NULL UNIQUE,
                seller_ua           TEXT NOT NULL,
                price_zat           INTEGER NOT NULL,
                burner_taddr        TEXT NOT NULL,
                burner_pubkey_hex   TEXT NOT NULL,
                mpc_path            TEXT NOT NULL,
                funded              INTEGER NOT NULL DEFAULT 0,
                created_at          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_listings_burner ON listings(burner_taddr);

            CREATE TABLE IF NOT EXISTS buyer_registrations (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                listing_id            INTEGER NOT NULL REFERENCES listings(id),
                buyer_ua              TEXT NOT NULL,
                buyer_signature_b64   TEXT NOT NULL,
                buyer_pubkey_b64      TEXT NOT NULL,
                admin_signature_b64  TEXT NOT NULL,
                is_sovereign          INTEGER NOT NULL DEFAULT 0,
                status                TEXT NOT NULL,
                created_at            TEXT NOT NULL,
                funding_txid          TEXT,
                funding_vout          INTEGER,
                build_height          INTEGER,
                payout_txid           TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_reg_listing ON buyer_registrations(listing_id);
            CREATE INDEX IF NOT EXISTS idx_reg_status  ON buyer_registrations(status);
            -- At most one awaiting/submitted registration per listing.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_reg_active
                ON buyer_registrations(listing_id)
                WHERE status IN ('awaiting_payment','submitted');
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

    // ── Listings ─────────────────────────────────────────────────────────

    pub fn upsert_listing(
        &self,
        contract_listing_id: i64,
        name: &str,
        seller_ua: &str,
        price_zat: u64,
        burner_taddr: &str,
        burner_pubkey_hex: &str,
        mpc_path: &str,
        funded: bool,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO listings (
                contract_listing_id, name, seller_ua, price_zat,
                burner_taddr, burner_pubkey_hex, mpc_path, funded, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(name) DO UPDATE SET
                 contract_listing_id = excluded.contract_listing_id,
                 seller_ua           = excluded.seller_ua,
                 price_zat           = excluded.price_zat,
                 burner_taddr        = excluded.burner_taddr,
                 burner_pubkey_hex   = excluded.burner_pubkey_hex,
                 mpc_path            = excluded.mpc_path,
                 funded              = excluded.funded",
            params![
                contract_listing_id,
                name,
                seller_ua,
                price_zat as i64,
                burner_taddr,
                burner_pubkey_hex,
                mpc_path,
                funded as i64,
                now,
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

    pub fn set_listing_funded(&self, contract_listing_id: i64, funded: bool) -> Result<()> {
        self.lock()?.execute(
            "UPDATE listings SET funded = ?1 WHERE contract_listing_id = ?2",
            params![funded as i64, contract_listing_id],
        )?;
        Ok(())
    }

    pub fn get_listing_by_id(&self, id: i64) -> Result<Option<Listing>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, contract_listing_id, name, seller_ua, price_zat,
                    burner_taddr, burner_pubkey_hex, mpc_path, funded, created_at
             FROM listings WHERE id = ?1",
            params![id],
            row_to_listing,
        )
        .optional()
        .context("get listing")
    }

    // ── Buyer registrations ──────────────────────────────────────────────

    pub fn insert_registration(
        &self,
        listing_id: i64,
        buyer_ua: &str,
        buyer_signature_b64: &str,
        buyer_pubkey_b64: &str,
        admin_signature_b64: &str,
        is_sovereign: bool,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO buyer_registrations (
                listing_id, buyer_ua, buyer_signature_b64, buyer_pubkey_b64,
                admin_signature_b64, is_sovereign, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                listing_id,
                buyer_ua,
                buyer_signature_b64,
                buyer_pubkey_b64,
                admin_signature_b64,
                is_sovereign as i64,
                RegistrationStatus::AwaitingPayment.as_str(),
                now,
            ],
        )
        .context("insert registration")?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_active_registration_for_listing(
        &self,
        listing_id: i64,
    ) -> Result<Option<BuyerRegistration>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, listing_id, buyer_ua, buyer_signature_b64, buyer_pubkey_b64,
                    admin_signature_b64, is_sovereign, status, created_at, funding_txid,
                    funding_vout, build_height, payout_txid
             FROM buyer_registrations
             WHERE listing_id = ?1 AND status IN ('awaiting_payment','submitted')
             LIMIT 1",
            params![listing_id],
            row_to_registration,
        )
        .optional()
        .context("get active registration")
    }

    pub fn list_active_registrations(&self) -> Result<Vec<BuyerRegistration>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, listing_id, buyer_ua, buyer_signature_b64, buyer_pubkey_b64,
                    admin_signature_b64, is_sovereign, status, created_at, funding_txid,
                    funding_vout, build_height, payout_txid
             FROM buyer_registrations
             WHERE status IN ('awaiting_payment','submitted')
             ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], row_to_registration)?;
        rows.collect::<Result<_, _>>().context("list active registrations")
    }

    pub fn mark_registration_submitted(
        &self,
        id: i64,
        funding_txid: &str,
        funding_vout: u32,
        build_height: u32,
    ) -> Result<()> {
        self.lock()?.execute(
            "UPDATE buyer_registrations
             SET status = ?1,
                 funding_txid = ?2,
                 funding_vout = ?3,
                 build_height = ?4
             WHERE id = ?5",
            params![
                RegistrationStatus::Submitted.as_str(),
                funding_txid,
                funding_vout as i64,
                build_height as i64,
                id,
            ],
        )?;
        Ok(())
    }

    pub fn mark_registration_completed(&self, id: i64, payout_txid: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE buyer_registrations
             SET status = ?1, payout_txid = ?2
             WHERE id = ?3",
            params![RegistrationStatus::Completed.as_str(), payout_txid, id],
        )?;
        Ok(())
    }
}

fn row_to_listing(row: &rusqlite::Row) -> rusqlite::Result<Listing> {
    let created_at_str: String = row.get(9)?;
    let created_at = created_at_str.parse::<DateTime<Utc>>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Listing {
        id: row.get(0)?,
        contract_listing_id: row.get(1)?,
        name: row.get(2)?,
        seller_ua: row.get(3)?,
        price_zat: row.get::<_, i64>(4)? as u64,
        burner_taddr: row.get(5)?,
        burner_pubkey_hex: row.get(6)?,
        mpc_path: row.get(7)?,
        funded: row.get::<_, i64>(8)? != 0,
        created_at,
    })
}

fn row_to_registration(row: &rusqlite::Row) -> rusqlite::Result<BuyerRegistration> {
    let status_str: String = row.get(7)?;
    let created_at_str: String = row.get(8)?;
    let status = RegistrationStatus::from_str(&status_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            e.to_string().into(),
        )
    })?;
    let created_at = created_at_str.parse::<DateTime<Utc>>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(BuyerRegistration {
        id: row.get(0)?,
        listing_id: row.get(1)?,
        buyer_ua: row.get(2)?,
        buyer_signature_b64: row.get(3)?,
        buyer_pubkey_b64: row.get(4)?,
        admin_signature_b64: row.get(5)?,
        is_sovereign: row.get::<_, i64>(6)? != 0,
        status,
        created_at,
        funding_txid: row.get(9)?,
        funding_vout: row.get(10)?,
        build_height: row.get(11)?,
        payout_txid: row.get(12)?,
    })
}
