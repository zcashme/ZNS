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
                name        TEXT PRIMARY KEY,
                ua          TEXT NOT NULL,
                txid        TEXT NOT NULL,
                height      INTEGER NOT NULL,
                nonce       INTEGER NOT NULL DEFAULT 0,
                signature   TEXT,
                last_action TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_registrations_ua ON registrations(ua);
            CREATE TABLE IF NOT EXISTS listings (
                name      TEXT PRIMARY KEY REFERENCES registrations(name),
                price     INTEGER NOT NULL,
                pay_taddr TEXT NOT NULL DEFAULT '',
                nonce     INTEGER NOT NULL,
                txid      TEXT NOT NULL,
                height    INTEGER NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                name      TEXT NOT NULL,
                action    TEXT NOT NULL,
                txid      TEXT NOT NULL UNIQUE,
                height    INTEGER NOT NULL,
                ua        TEXT,
                price     INTEGER,
                nonce     INTEGER,
                signature TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_name   ON events(name);
            CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
            CREATE INDEX IF NOT EXISTS idx_events_height ON events(height);
            CREATE TABLE IF NOT EXISTS pending_buys (
                name        TEXT PRIMARY KEY REFERENCES registrations(name),
                buyer_ua    TEXT NOT NULL,
                price       INTEGER NOT NULL,
                pay_taddr   TEXT NOT NULL,
                claim_height INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                txid        TEXT NOT NULL,
                signature   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_buys_pay_taddr ON pending_buys(pay_taddr);
            CREATE INDEX IF NOT EXISTS idx_pending_buys_expires ON pending_buys(expires_at);
            CREATE TABLE IF NOT EXISTS pricing (
                id        INTEGER PRIMARY KEY CHECK (id = 1),
                nonce     INTEGER NOT NULL,
                tiers     TEXT NOT NULL,
                height    INTEGER NOT NULL,
                txid      TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_roots (
                height     INTEGER PRIMARY KEY,
                root       BLOB    NOT NULL,
                leaf_count INTEGER NOT NULL
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
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO registrations (name, ua, signature, txid, height, last_action) VALUES (?1, ?2, ?3, ?4, ?5, 'CLAIM')",
            rusqlite::params![name, ua, signature, txid, height as i64],
        )?;
        if tx.changes() == 0 {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, ua, price, nonce, signature)
             VALUES (?1, 'CLAIM', ?2, ?3, ?4, NULL, NULL, ?5)",
            rusqlite::params![name, txid, height as i64, ua, signature],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn create_listing(
        &self,
        name: &str,
        price: u64,
        pay_taddr: &str,
        nonce: u64,
        signature: &str,
        txid: &str,
        height: u64,
    ) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO listings (name, price, pay_taddr, nonce, signature, txid, height) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![name, price as i64, pay_taddr, nonce as i64, signature, txid, height as i64],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, price, nonce, signature)
             VALUES (?1, 'LIST', ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![name, txid, height as i64, price as i64, nonce as i64, signature],
        )?;
        tx.commit()?;
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

    /// Finalize a sale atomically: transfer ownership, drop the listing and
    /// pending buy, and record the BUY event in a single transaction so a
    /// crash mid-finalize cannot lose the event after the transfer is durable.
    pub fn finalize_buy(
        &self,
        name: &str,
        new_ua: &str,
        signature: &str,
        payment_txid: &str,
        payment_height: u64,
        price: u64,
    ) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, nonce = 0, signature = ?4, last_action = 'BUY' WHERE name = ?5",
            rusqlite::params![new_ua, payment_txid, payment_height as i64, signature, name],
        )?;
        tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
        tx.execute("DELETE FROM pending_buys WHERE name = ?1", [name])?;
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, ua, price, nonce, signature)
             VALUES (?1, 'BUY', ?2, ?3, ?4, ?5, NULL, ?6)",
            rusqlite::params![name, payment_txid, payment_height as i64, new_ua, price as i64, signature],
        )?;
        tx.commit()
    }

    // ── Pending buy lifecycle ───────────────────────────────────────────────

    pub fn create_pending_buy(
        &self,
        name: &str,
        buyer_ua: &str,
        price: u64,
        pay_taddr: &str,
        claim_height: u64,
        expires_at: u64,
        txid: &str,
        signature: &str,
    ) -> rusqlite::Result<bool> {
        self.db.execute(
            // OR REPLACE so a fresh BUY at height H supersedes a stale row from
            // an earlier expired BUY on the same name. The caller (handle_action)
            // already gates on existing.expires_at < height before reaching us,
            // so a replace here can never overwrite an active lock.
            "INSERT OR REPLACE INTO pending_buys
             (name, buyer_ua, price, pay_taddr, claim_height, expires_at, txid, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                name,
                buyer_ua,
                price as i64,
                pay_taddr,
                claim_height as i64,
                expires_at as i64,
                txid,
                signature,
            ],
        )?;
        Ok(self.db.changes() > 0)
    }

    pub fn has_conflicting_pending_buy(
        &self,
        pay_taddr: &str,
        price: u64,
        name: &str,
        current_height: u64,
    ) -> bool {
        self.db
            .query_row(
                "SELECT 1 FROM pending_buys
                 WHERE pay_taddr = ?1 AND price = ?2 AND name != ?3 AND expires_at >= ?4
                 LIMIT 1",
                rusqlite::params![pay_taddr, price as i64, name, current_height as i64],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn canonical_pending_for_payment(
        &self,
        pay_taddr: &str,
        price: u64,
        current_height: u64,
    ) -> Option<PendingBuy> {
        self.db
            .query_row(
                "SELECT name, buyer_ua, price, pay_taddr, claim_height, expires_at, txid, signature
                 FROM pending_buys
                 WHERE pay_taddr = ?1 AND price = ?2 AND expires_at >= ?3
                 ORDER BY claim_height ASC, name ASC
                 LIMIT 1",
                rusqlite::params![pay_taddr, price as i64, current_height as i64],
                |row| {
                    Ok(PendingBuy {
                        name: row.get(0)?,
                        buyer: row.get(1)?,
                        price: row.get::<_, i64>(2)? as u64,
                        pay_taddr: row.get(3)?,
                        claim_height: row.get::<_, i64>(4)? as u64,
                        expires_at: row.get::<_, i64>(5)? as u64,
                        txid: row.get(6)?,
                        signature: row.get(7)?,
                    })
                },
            )
            .ok()
    }

    pub fn get_pending_buy(&self, name: &str) -> Option<PendingBuy> {
        self.db
            .query_row(
                "SELECT name, buyer_ua, price, pay_taddr, claim_height, expires_at, txid, signature
                 FROM pending_buys WHERE name = ?1",
                [name],
                |row| {
                    Ok(PendingBuy {
                        name: row.get(0)?,
                        buyer: row.get(1)?,
                        price: row.get::<_, i64>(2)? as u64,
                        pay_taddr: row.get(3)?,
                        claim_height: row.get::<_, i64>(4)? as u64,
                        expires_at: row.get::<_, i64>(5)? as u64,
                        txid: row.get(6)?,
                        signature: row.get(7)?,
                    })
                },
            )
            .ok()
    }

    pub fn list_active_pending_buys(&self, current_height: u64) -> Vec<PendingBuy> {
        let Ok(mut stmt) = self.db.prepare(
            "SELECT name, buyer_ua, price, pay_taddr, claim_height, expires_at, txid, signature
             FROM pending_buys WHERE expires_at >= ?1
             ORDER BY claim_height ASC, name ASC",
        ) else {
            return vec![];
        };
        let rows = stmt.query_map([current_height as i64], |row| {
            Ok(PendingBuy {
                name: row.get(0)?,
                buyer: row.get(1)?,
                price: row.get::<_, i64>(2)? as u64,
                pay_taddr: row.get(3)?,
                claim_height: row.get::<_, i64>(4)? as u64,
                expires_at: row.get::<_, i64>(5)? as u64,
                txid: row.get(6)?,
                signature: row.get(7)?,
            })
        });
        match rows {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        }
    }

    /// Removes pending buys whose `expires_at` is below `current_height`.
    /// Returns the names that were dropped, for logging.
    pub fn expire_pending_buys(&self, current_height: u64) -> Vec<String> {
        let Ok(mut stmt) = self
            .db
            .prepare("SELECT name FROM pending_buys WHERE expires_at < ?1")
        else {
            return vec![];
        };
        let names: Vec<String> = match stmt.query_map([current_height as i64], |row| row.get(0)) {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(_) => return vec![],
        };
        let _ = self.db.execute(
            "DELETE FROM pending_buys WHERE expires_at < ?1",
            [current_height as i64],
        );
        names
    }

    pub fn delete_listing(&self, name: &str, signature: &str, txid: &str, height: u64, nonce: u64) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE registrations SET signature = ?1, last_action = 'DELIST' WHERE name = ?2",
            rusqlite::params![signature, name],
        )?;
        tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, nonce, signature)
             VALUES (?1, 'DELIST', ?2, ?3, ?4, ?5)",
            rusqlite::params![name, txid, height as i64, nonce as i64, signature],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_registration(&self, name: &str, txid: &str, height: u64, nonce: u64, signature: &str) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
        tx.execute("DELETE FROM registrations WHERE name = ?1", [name])?;
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, nonce, signature)
             VALUES (?1, 'RELEASE', ?2, ?3, ?4, ?5)",
            rusqlite::params![name, txid, height as i64, nonce as i64, signature],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_address(
        &self,
        name: &str,
        new_ua: &str,
        signature: &str,
        txid: &str,
        height: u64,
    ) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, signature = ?4, last_action = 'UPDATE' WHERE name = ?5",
            rusqlite::params![new_ua, txid, height as i64, signature, name],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, ua, nonce, signature)
             VALUES (?1, 'UPDATE', ?2, ?3, ?4, NULL, ?5)",
            rusqlite::params![name, txid, height as i64, new_ua, signature],
        )?;
        tx.commit()?;
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
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO pricing (id, nonce, tiers, height, txid, signature) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![nonce as i64, tiers_json, height as i64, txid, signature],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO events (name, action, txid, height, nonce, signature)
             VALUES ('SETPRICE', 'SETPRICE', ?1, ?2, ?3, ?4)",
            rusqlite::params![txid, height as i64, nonce as i64, signature],
        )?;
        tx.commit()?;
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

    // ── Reads ───────────────────────────────────────────────────────────────

    pub fn resolve_by_name(&self, name: &str) -> Option<Registration> {
        self.db
            .query_row(
                "SELECT name, ua, txid, height, nonce, signature, last_action FROM registrations WHERE name = ?1",
                [name],
                |row| {
                    Ok(Registration {
                        name: row.get(0)?,
                        address: row.get(1)?,
                        txid: row.get(2)?,
                        height: row.get::<_, i64>(3)? as u64,
                        nonce: row.get::<_, i64>(4)? as u64,
                        signature: row.get(5)?,
                        last_action: row.get(6)?,
                    })
                },
            )
            .ok()
    }

    pub fn get_listing(&self, name: &str) -> Option<Listing> {
        self.db
            .query_row(
                "SELECT name, price, pay_taddr, nonce, txid, height, signature FROM listings WHERE name = ?1",
                [name],
                |row| {
                    Ok(Listing {
                        name: row.get(0)?,
                        price: row.get::<_, i64>(1)? as u64,
                        pay_taddr: row.get(2)?,
                        nonce: row.get::<_, i64>(3)? as u64,
                        txid: row.get(4)?,
                        height: row.get::<_, i64>(5)? as u64,
                        signature: row.get(6)?,
                    })
                },
            )
            .ok()
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

    pub fn list_registrations(&self, limit: u64, offset: u64) -> Vec<Registration> {
        let Ok(mut stmt) = self.db.prepare(
            "SELECT name, ua, txid, height, nonce, signature, last_action
             FROM registrations
             ORDER BY height DESC LIMIT ?1 OFFSET ?2",
        ) else {
            return vec![];
        };
        let Ok(rows) = stmt.query_map([limit as i64, offset as i64], |row| {
            Ok(Registration {
                name: row.get(0)?,
                address: row.get(1)?,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                nonce: row.get::<_, i64>(4)? as u64,
                signature: row.get(5)?,
                last_action: row.get(6)?,
            })
        }) else {
            return vec![];
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn list_registrations_by_address(
        &self,
        address: &str,
        limit: u64,
        offset: u64,
    ) -> Vec<Registration> {
        let Ok(mut stmt) = self.db.prepare(
            "SELECT name, ua, txid, height, nonce, signature, last_action
             FROM registrations
             WHERE ua = ?1
             ORDER BY height DESC LIMIT ?2 OFFSET ?3",
        ) else {
            return vec![];
        };
        let Ok(rows) = stmt.query_map(
            rusqlite::params![address, limit as i64, offset as i64],
            |row| {
                Ok(Registration {
                    name: row.get(0)?,
                    address: row.get(1)?,
                    txid: row.get(2)?,
                    height: row.get::<_, i64>(3)? as u64,
                    nonce: row.get::<_, i64>(4)? as u64,
                    signature: row.get(5)?,
                    last_action: row.get(6)?,
                })
            },
        ) else {
            return vec![];
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn list_listings(&self, limit: u64, offset: u64) -> Vec<Listing> {
        let Ok(mut stmt) = self.db.prepare(
            "SELECT name, price, pay_taddr, nonce, txid, height, signature
             FROM listings
             ORDER BY height DESC LIMIT ?1 OFFSET ?2",
        ) else {
            return vec![];
        };
        let Ok(rows) = stmt.query_map([limit as i64, offset as i64], |row| {
            Ok(Listing {
                name: row.get(0)?,
                price: row.get::<_, i64>(1)? as u64,
                pay_taddr: row.get(2)?,
                nonce: row.get::<_, i64>(3)? as u64,
                txid: row.get(4)?,
                height: row.get::<_, i64>(5)? as u64,
                signature: row.get(6)?,
            })
        }) else {
            return vec![];
        };
        rows.filter_map(|r| r.ok()).collect()
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

    /// Returns the minimum raw pricing tier in zatoshis (before scaling), or `None`
    /// if no pricing is set. Multiply by 10_000 to get the actual zatoshi amount.
    pub fn min_tier(&self) -> Option<u64> {
        let tiers_str: String = self
            .db
            .query_row("SELECT tiers FROM pricing WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()?;
        tiers_str
            .split(':')
            .filter_map(|s| s.parse::<u64>().ok())
            .min()
    }

    // ── State-root commitment ───────────────────────────────────────────────

    /// All registrations ordered by name — the canonical leaf order for the
    /// Merkle tree. Reads the same columns as `resolve_by_name` so leaf hashing
    /// can use the existing `Registration` struct.
    pub fn all_registrations_sorted(&self) -> Vec<Registration> {
        let Ok(mut stmt) = self.db.prepare(
            "SELECT name, ua, txid, height, nonce, signature, last_action
             FROM registrations ORDER BY name",
        ) else {
            return vec![];
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok(Registration {
                name: row.get(0)?,
                address: row.get(1)?,
                txid: row.get(2)?,
                height: row.get::<_, i64>(3)? as u64,
                nonce: row.get::<_, i64>(4)? as u64,
                signature: row.get(5)?,
                last_action: row.get(6)?,
            })
        }) else {
            return vec![];
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn store_state_root(
        &self,
        height: u64,
        root: &[u8; 32],
        leaf_count: u64,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO state_roots (height, root, leaf_count)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![height as i64, root.as_slice(), leaf_count as i64],
        )?;
        Ok(())
    }

    pub fn get_latest_state_root(&self) -> Option<StateRoot> {
        self.db
            .query_row(
                "SELECT height, root, leaf_count FROM state_roots
                 ORDER BY height DESC LIMIT 1",
                [],
                |row| {
                    let root_bytes: Vec<u8> = row.get(1)?;
                    let mut root = [0u8; 32];
                    if root_bytes.len() == 32 {
                        root.copy_from_slice(&root_bytes);
                    }
                    Ok(StateRoot {
                        height: row.get::<_, i64>(0)? as u64,
                        root,
                        leaf_count: row.get::<_, i64>(2)? as u64,
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

        let bind_refs: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
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
        let bind_refs: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();

        let mut stmt = match self.db.prepare(&query_sql) {
            Ok(s) => s,
            Err(_) => {
                return EventPage {
                    events: vec![],
                    total,
                };
            }
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

#[derive(Debug, Clone)]
pub struct Registration {
    pub name: String,
    pub address: String,
    pub txid: String,
    pub height: u64,
    pub nonce: u64,
    pub signature: Option<String>,
    pub last_action: String,
}

#[derive(Debug, Clone)]
pub struct Listing {
    pub name: String,
    pub price: u64,
    pub pay_taddr: String,
    pub nonce: u64,
    pub txid: String,
    pub height: u64,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct PendingBuy {
    pub name: String,
    pub buyer: String,
    pub price: u64,
    pub pay_taddr: String,
    pub claim_height: u64,
    pub expires_at: u64,
    pub txid: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct Pricing {
    pub nonce: u64,
    pub height: u64,
    pub tiers: Vec<u64>,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub total: u64,
}

#[derive(Debug, Clone)]
pub struct StateRoot {
    pub height: u64,
    pub root: [u8; 32],
    pub leaf_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TADDR: &str = "tmqY61Gp3B7Pz3ev12NRFzWxJz1yB28Gfkfi";

    fn mem_registry() -> Registry {
        Registry::open(":memory:").expect("in-memory db")
    }

    fn seed_name(reg: &Registry, name: &str) {
        reg.create_registration(name, "u1example", "sig", &format!("tx-{name}"), 1)
            .expect("registration");
    }

    #[test]
    fn detects_conflicting_pending_buys() {
        let reg = mem_registry();
        seed_name(&reg, "alice");
        seed_name(&reg, "bob");
        reg.create_pending_buy("alice", "buyer1", 100, TADDR, 10, 200, "tx-a", "sig")
            .expect("pending alice");
        assert!(reg.has_conflicting_pending_buy(TADDR, 100, "bob", 10));
        assert!(!reg.has_conflicting_pending_buy(TADDR, 100, "alice", 10));
    }

    #[test]
    fn canonical_pending_is_earliest_claim() {
        let reg = mem_registry();
        seed_name(&reg, "alice");
        seed_name(&reg, "bob");
        reg.create_pending_buy("bob", "buyer2", 100, TADDR, 20, 200, "tx-b", "sig")
            .expect("pending bob");
        reg.create_pending_buy("alice", "buyer1", 100, TADDR, 10, 200, "tx-a", "sig")
            .expect("pending alice");
        let canonical = reg
            .canonical_pending_for_payment(TADDR, 100, 15)
            .expect("canonical");
        assert_eq!(canonical.name, "alice");
    }
}
