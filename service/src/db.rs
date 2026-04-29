use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

/// SQLite-backed intent store.  Single source of truth for the service.
///
/// Wrapped in a [`Mutex`] so it can be shared across async tasks.
pub struct IntentStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Intent {
    pub id: i64,
    pub name: String,
    pub buyer_ua: String,
    pub buyer_taddr: Option<String>,
    pub price_zat: u64,
    pub burner_taddr: String,
    pub mpc_path: String,
    pub status: IntentStatus,
    pub zcash_txid: Option<String>,
    pub unsigned_tx_hash: Option<String>,
    pub payout_txid: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentStatus {
    PendingPayment,
    PaymentConfirmed,
    PayoutPending,
    Completed,
    Expired,
}

impl IntentStatus {
    fn as_str(&self) -> &'static str {
        match self {
            IntentStatus::PendingPayment => "pending_payment",
            IntentStatus::PaymentConfirmed => "payment_confirmed",
            IntentStatus::PayoutPending => "payout_pending",
            IntentStatus::Completed => "completed",
            IntentStatus::Expired => "expired",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pending_payment" => Ok(IntentStatus::PendingPayment),
            "payment_confirmed" => Ok(IntentStatus::PaymentConfirmed),
            "payout_pending" => Ok(IntentStatus::PayoutPending),
            "completed" => Ok(IntentStatus::Completed),
            "expired" => Ok(IntentStatus::Expired),
            _ => bail!("unknown intent status: {}", s),
        }
    }
}

impl IntentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open SQLite")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS intents (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                buyer_ua      TEXT NOT NULL,
                buyer_taddr   TEXT,
                price_zat     INTEGER NOT NULL,
                burner_taddr  TEXT NOT NULL UNIQUE,
                mpc_path      TEXT NOT NULL,
                status        TEXT NOT NULL,
                zcash_txid    TEXT,
                unsigned_tx_hash TEXT,
                payout_txid   TEXT,
                created_at    TEXT NOT NULL,
                expires_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_intents_status ON intents(status);
            CREATE INDEX IF NOT EXISTS idx_intents_burner ON intents(burner_taddr);
            CREATE INDEX IF NOT EXISTS idx_intents_name   ON intents(name);
            "#,
        )
        .context("create intents table")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|e| anyhow::anyhow!("poison: {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_intent(
        &self,
        name: &str,
        buyer_ua: &str,
        buyer_taddr: Option<&str>,
        price_zat: u64,
        burner_taddr: &str,
        mpc_path: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let exp = expires_at.to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO intents (name, buyer_ua, buyer_taddr, price_zat, burner_taddr, mpc_path, status, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                name, buyer_ua, buyer_taddr, price_zat as i64, burner_taddr, mpc_path,
                IntentStatus::PendingPayment.as_str(), now, exp
            ],
        ).context("insert intent")?;
        Ok(conn.last_insert_rowid())
    }

    #[allow(dead_code)]
    pub fn get_intent_by_id(&self, id: i64) -> Result<Option<Intent>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, buyer_ua, buyer_taddr, price_zat, burner_taddr, mpc_path,
                        status, zcash_txid, unsigned_tx_hash, payout_txid, created_at, expires_at
                 FROM intents WHERE id = ?1",
            params![id],
            |row| self.row_to_intent(row),
        )
        .optional()
        .context("get intent")
    }

    #[allow(dead_code)]
    pub fn get_intent_by_burner(&self, burner: &str) -> Result<Option<Intent>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, buyer_ua, buyer_taddr, price_zat, burner_taddr, mpc_path,
                        status, zcash_txid, unsigned_tx_hash, payout_txid, created_at, expires_at
                 FROM intents WHERE burner_taddr = ?1",
            params![burner],
            |row| self.row_to_intent(row),
        )
        .optional()
        .context("get intent by burner")
    }

    pub fn list_active_intents(&self) -> Result<Vec<Intent>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, buyer_ua, buyer_taddr, price_zat, burner_taddr, mpc_path,
                    status, zcash_txid, unsigned_tx_hash, payout_txid, created_at, expires_at
             FROM intents
             WHERE status IN ('pending_payment', 'payment_confirmed', 'payout_pending')
             ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| self.row_to_intent(row))?;
        rows.collect::<Result<_, _>>()
            .context("list active intents")
    }

    #[allow(dead_code)]
    pub fn update_status(&self, id: i64, status: IntentStatus) -> Result<()> {
        self.lock()?.execute(
            "UPDATE intents SET status = ?1 WHERE id = ?2",
            params![status.as_str(), id],
        )?;
        Ok(())
    }

    pub fn set_zcash_txid(&self, id: i64, txid: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE intents SET zcash_txid = ?1, status = ?2 WHERE id = ?3",
            params![txid, IntentStatus::PaymentConfirmed.as_str(), id],
        )?;
        Ok(())
    }

    pub fn set_payout_pending(&self, id: i64, unsigned_tx_hash: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE intents SET unsigned_tx_hash = ?1, status = ?2 WHERE id = ?3",
            params![unsigned_tx_hash, IntentStatus::PayoutPending.as_str(), id],
        )?;
        Ok(())
    }

    pub fn set_completed(&self, id: i64, payout_txid: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE intents SET payout_txid = ?1, status = ?2 WHERE id = ?3",
            params![payout_txid, IntentStatus::Completed.as_str(), id],
        )?;
        Ok(())
    }

    pub fn set_expired(&self, id: i64) -> Result<()> {
        self.lock()?.execute(
            "UPDATE intents SET status = ?1 WHERE id = ?2",
            params![IntentStatus::Expired.as_str(), id],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn update_mpc_path(&self, id: i64, path: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE intents SET mpc_path = ?1 WHERE id = ?2",
            params![path, id],
        )?;
        Ok(())
    }

    fn row_to_intent(&self, row: &rusqlite::Row) -> rusqlite::Result<Intent> {
        let status_str: String = row.get(7)?;
        let created_at_str: String = row.get(11)?;
        let expires_at_str: String = row.get(12)?;

        let to_sql_err = |idx, e: Box<dyn std::error::Error + Send + Sync + 'static>| {
            rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, e)
        };

        let status =
            IntentStatus::from_str(&status_str).map_err(|e| to_sql_err(7, e.to_string().into()))?;

        let created_at = created_at_str
            .parse::<DateTime<Utc>>()
            .map_err(|e| to_sql_err(11, Box::new(e)))?;

        let expires_at = expires_at_str
            .parse::<DateTime<Utc>>()
            .map_err(|e| to_sql_err(12, Box::new(e)))?;

        Ok(Intent {
            id: row.get(0)?,
            name: row.get(1)?,
            buyer_ua: row.get(2)?,
            buyer_taddr: row.get(3)?,
            price_zat: row.get::<_, i64>(4)? as u64,
            burner_taddr: row.get(5)?,
            mpc_path: row.get(6)?,
            status,
            zcash_txid: row.get(8)?,
            unsigned_tx_hash: row.get(9)?,
            payout_txid: row.get(10)?,
            created_at,
            expires_at,
        })
    }
}
