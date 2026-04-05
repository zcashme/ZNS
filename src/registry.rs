// ZNS registry — complete data-access layer for the indexer's SQLite database.

use rusqlite::Connection;

pub struct Registry {
    db: Connection,
}

impl Registry {
    /// Opens (or creates) the registry database and ensures the schema exists.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS registrations (
                name      TEXT PRIMARY KEY,
                ua        TEXT NOT NULL,
                txid      TEXT NOT NULL,
                height    INTEGER NOT NULL,
                nonce     INTEGER NOT NULL DEFAULT 0,
                signature TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_registrations_ua ON registrations(ua);
            CREATE TABLE IF NOT EXISTS listings (
                name      TEXT PRIMARY KEY REFERENCES registrations(name),
                price     INTEGER NOT NULL,
                txid      TEXT NOT NULL,
                height    INTEGER NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                name      TEXT NOT NULL,
                action    TEXT NOT NULL,
                txid      TEXT NOT NULL,
                height    INTEGER NOT NULL,
                ua        TEXT,
                price     INTEGER,
                nonce     INTEGER,
                signature TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_name   ON events(name);
            CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
            CREATE INDEX IF NOT EXISTS idx_events_height ON events(height);
            CREATE TABLE IF NOT EXISTS pricing (
                id        INTEGER PRIMARY KEY CHECK (id = 1),
                nonce     INTEGER NOT NULL,
                tiers     TEXT NOT NULL,
                height    INTEGER NOT NULL,
                txid      TEXT NOT NULL,
                signature TEXT NOT NULL
            );",
        )?;
        Ok(Registry { db })
    }

    // ── Writes ──────────────────────────────────────────────────────────────

    pub fn is_registered(&self, name: &str) -> bool {
        self.db
            .query_row(
                "SELECT 1 FROM registrations WHERE name = ?1",
                [name],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn validate_and_increment_nonce(&self, name: &str, nonce: u64) -> Result<(), String> {
        let current: u64 = self
            .db
            .query_row(
                "SELECT nonce FROM registrations WHERE name = ?1",
                [name],
                |row| Ok(row.get::<_, i64>(0)? as u64),
            )
            .map_err(|_| format!("unregistered name {name}"))?;
        if nonce <= current {
            return Err(format!(
                "replay rejected for {name}: nonce {nonce} <= {current}"
            ));
        }
        self.db
            .execute(
                "UPDATE registrations SET nonce = ?1 WHERE name = ?2",
                rusqlite::params![nonce as i64, name],
            )
            .map_err(|e| format!("DB error (nonce): {e}"))?;
        Ok(())
    }

    pub fn create_registration(
        &self,
        name: &str,
        ua: &str,
        signature: &str,
        txid: &str,
        height: u64,
    ) -> rusqlite::Result<bool> {
        self.db.execute(
            "INSERT OR IGNORE INTO registrations (name, ua, signature, txid, height) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, ua, signature, txid, height as i64],
        )?;
        Ok(self.db.changes() > 0)
    }

    pub fn create_listing(
        &self,
        name: &str,
        price: u64,
        signature: &str,
        txid: &str,
        height: u64,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO listings (name, price, signature, txid, height) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, price as i64, signature, txid, height as i64],
        )?;
        Ok(())
    }

    pub fn get_listing_price(&self, name: &str) -> Option<u64> {
        self.db
            .query_row(
                "SELECT price FROM listings WHERE name = ?1",
                [name],
                |row| Ok(row.get::<_, i64>(0)? as u64),
            )
            .ok()
    }

    pub fn process_buy(
        &self,
        name: &str,
        new_ua: &str,
        signature: &str,
        txid: &str,
        height: u64,
    ) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, nonce = 0, signature = ?4 WHERE name = ?5",
            rusqlite::params![new_ua, txid, height as i64, signature, name],
        )?;
        tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
        tx.commit()
    }

    pub fn delete_listing(&self, name: &str, signature: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE registrations SET signature = ?1 WHERE name = ?2",
            rusqlite::params![signature, name],
        )?;
        self.db
            .execute("DELETE FROM listings WHERE name = ?1", [name])?;
        Ok(())
    }

    pub fn delete_registration(&self, name: &str) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
        tx.execute("DELETE FROM registrations WHERE name = ?1", [name])?;
        tx.commit()
    }

    pub fn update_address(
        &self,
        name: &str,
        new_ua: &str,
        signature: &str,
        txid: &str,
        height: u64,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, signature = ?4 WHERE name = ?5",
            rusqlite::params![new_ua, txid, height as i64, signature, name],
        )?;
        Ok(())
    }

    pub fn get_owner_ua(&self, name: &str) -> Option<String> {
        self.db
            .query_row(
                "SELECT ua FROM registrations WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .ok()
    }

    pub fn get_pricing_nonce(&self) -> Option<u64> {
        self.db
            .query_row("SELECT nonce FROM pricing WHERE id = 1", [], |row| {
                Ok(row.get::<_, i64>(0)? as u64)
            })
            .ok()
    }

    pub fn store_pricing(
        &self,
        nonce: u64,
        height: u64,
        tiers_json: &str,
        txid: &str,
        signature: &str,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO pricing (id, nonce, tiers, height, txid, signature) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![nonce as i64, tiers_json, height as i64, txid, signature],
        )?;
        Ok(())
    }

    pub fn lookup_claim_cost(&self, name_len: usize) -> Option<u64> {
        let tiers_str: String = self
            .db
            .query_row("SELECT tiers FROM pricing WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()?;
        let tiers: Vec<u64> = tiers_str
            .split(':')
            .filter_map(|s| s.parse().ok())
            .collect();
        if tiers.is_empty() {
            return None;
        }
        let idx = (name_len.saturating_sub(1)).min(tiers.len() - 1);
        Some(tiers[idx] * 10_000)
    }

    pub fn insert_event(
        &self,
        name: &str,
        action: &str,
        txid: &str,
        height: u64,
        ua: Option<&str>,
        price: Option<u64>,
        nonce: Option<u64>,
        signature: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO events (name, action, txid, height, ua, price, nonce, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                name,
                action,
                txid,
                height as i64,
                ua,
                price.map(|p| p as i64),
                nonce.map(|n| n as i64),
                signature,
            ],
        )?;
        Ok(())
    }

    // ── Reads ───────────────────────────────────────────────────────────────

    pub fn resolve_by_name(&self, name: &str) -> Option<Registration> {
        self.db
            .query_row(
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

    pub fn resolve_by_address(&self, address: &str) -> Vec<Registration> {
        let mut stmt = match self.db.prepare(
            "SELECT name, ua, txid, height, nonce, signature FROM registrations WHERE ua = ?1",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map([address], |row| {
            Ok(Registration {
                name: row.get(0)?,
                address: row.get(1)?,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                nonce: row.get::<_, i64>(4)? as u64,
                signature: row.get(5)?,
            })
        })
        .unwrap_or_else(|_| panic!("query failed"))
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn get_listing(&self, name: &str) -> Option<Listing> {
        self.db
            .query_row(
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

    pub fn list_for_sale(&self) -> Vec<Listing> {
        let mut stmt = match self.db.prepare(
            "SELECT l.name, l.price, l.txid, l.height, l.signature
             FROM listings l
             ORDER BY l.height DESC",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map([], |row| {
            Ok(Listing {
                name: row.get(0)?,
                price: row.get::<_, i64>(1)? as u64,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                signature: row.get(4)?,
            })
        })
        .unwrap_or_else(|_| panic!("query failed"))
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn count_registrations(&self) -> u64 {
        self.db
            .query_row("SELECT COUNT(*) FROM registrations", [], |row| {
                Ok(row.get::<_, i64>(0)? as u64)
            })
            .unwrap_or(0)
    }

    pub fn count_listings(&self) -> u64 {
        self.db
            .query_row("SELECT COUNT(*) FROM listings", [], |row| {
                Ok(row.get::<_, i64>(0)? as u64)
            })
            .unwrap_or(0)
    }

    pub fn get_pricing(&self) -> Option<Pricing> {
        self.db
            .query_row(
                "SELECT nonce, height, tiers FROM pricing WHERE id = 1",
                [],
                |row| {
                    let tiers_str: String = row.get(2)?;
                    let tiers: Vec<u64> = tiers_str
                        .split(':')
                        .filter_map(|s| s.parse::<u64>().ok())
                        .map(|t| t * 10_000)
                        .collect();
                    Ok(Pricing {
                        nonce: row.get::<_, i64>(0)? as u64,
                        height: row.get::<_, i64>(1)? as u64,
                        tiers,
                    })
                },
            )
            .ok()
    }

    pub fn query_events(
        &self,
        name: Option<&str>,
        actions: &[&str],
        since_height: Option<u64>,
        limit: u64,
        offset: u64,
    ) -> EventPage {
        let mut conditions = Vec::new();
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(n) = name {
            conditions.push(format!("name = ?{}", bind.len() + 1));
            bind.push(Box::new(n.to_string()));
        }
        if !actions.is_empty() {
            let placeholders: Vec<String> = actions
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", bind.len() + i + 1))
                .collect();
            conditions.push(format!("action IN ({})", placeholders.join(",")));
            for a in actions {
                bind.push(Box::new(a.to_string()));
            }
        }
        if let Some(h) = since_height {
            conditions.push(format!("height > ?{}", bind.len() + 1));
            bind.push(Box::new(h as i64));
        }

        let where_clause = if conditions.is_empty() {
            "1=1".to_string()
        } else {
            conditions.join(" AND ")
        };

        let bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind.iter().map(|b| b.as_ref()).collect();
        let total: u64 = self
            .db
            .query_row(
                &format!("SELECT COUNT(*) FROM events WHERE {where_clause}"),
                &*bind_refs,
                |row| Ok(row.get::<_, i64>(0)? as u64),
            )
            .unwrap_or(0);

        let query_sql = format!(
            "SELECT id, name, action, txid, height, ua, price, nonce, signature \
             FROM events WHERE {where_clause} ORDER BY height DESC, id DESC LIMIT ?{} OFFSET ?{}",
            bind.len() + 1,
            bind.len() + 2,
        );
        bind.push(Box::new(limit as i64));
        bind.push(Box::new(offset as i64));
        let bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind.iter().map(|b| b.as_ref()).collect();

        let mut stmt = match self.db.prepare(&query_sql) {
            Ok(s) => s,
            Err(_) => return EventPage { events: vec![], total },
        };
        let events = match stmt.query_map(&*bind_refs, |row| {
            Ok(Event {
                id: row.get::<_, i64>(0)? as u64,
                name: row.get(1)?,
                action: row.get(2)?,
                txid: row.get(3)?,
                height: row.get::<_, i64>(4)? as u64,
                ua: row.get(5)?,
                price: row.get::<_, Option<i64>>(6)?.map(|p| p as u64),
                nonce: row.get::<_, Option<i64>>(7)?.map(|n| n as u64),
                signature: row.get(8)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        };

        EventPage { events, total }
    }
}

// ── Data types ──────────────────────────────────────────────────────────────

pub struct Registration {
    pub name: String,
    pub address: String,
    pub txid: String,
    pub height: u64,
    pub nonce: u64,
    pub signature: Option<String>,
}

pub struct Listing {
    pub name: String,
    pub price: u64,
    pub txid: String,
    pub height: u64,
    pub signature: String,
}

pub struct Pricing {
    pub nonce: u64,
    pub height: u64,
    pub tiers: Vec<u64>,
}

pub struct Event {
    pub id: u64,
    pub name: String,
    pub action: String,
    pub txid: String,
    pub height: u64,
    pub ua: Option<String>,
    pub price: Option<u64>,
    pub nonce: Option<u64>,
    pub signature: Option<String>,
}

pub struct EventPage {
    pub events: Vec<Event>,
    pub total: u64,
}
