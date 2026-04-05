// ZNS registry — SQLite write path for the indexer.

use rusqlite::Connection;

/// Opens (or creates) the registry database and ensures the schema exists.
pub fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
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
    Ok(conn)
}

pub fn is_registered(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM registrations WHERE name = ?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

pub fn validate_and_increment_nonce(db: &Connection, name: &str, nonce: u64) -> Result<(), String> {
    let current: u64 = db
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
    db.execute(
        "UPDATE registrations SET nonce = ?1 WHERE name = ?2",
        rusqlite::params![nonce as i64, name],
    )
    .map_err(|e| format!("DB error (nonce): {e}"))?;
    Ok(())
}

/// Returns true if a new row was actually inserted.
pub fn create_registration(
    db: &Connection,
    name: &str,
    ua: &str,
    signature: &str,
    txid: &str,
    height: u64,
) -> rusqlite::Result<bool> {
    db.execute(
        "INSERT OR IGNORE INTO registrations (name, ua, signature, txid, height) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![name, ua, signature, txid, height as i64],
    )?;
    Ok(db.changes() > 0)
}

pub fn create_listing(
    db: &Connection,
    name: &str,
    price: u64,
    signature: &str,
    txid: &str,
    height: u64,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO listings (name, price, signature, txid, height) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![name, price as i64, signature, txid, height as i64],
    )?;
    Ok(())
}

pub fn get_listing_price(db: &Connection, name: &str) -> Option<u64> {
    db.query_row(
        "SELECT price FROM listings WHERE name = ?1",
        [name],
        |row| Ok(row.get::<_, i64>(0)? as u64),
    )
    .ok()
}

pub fn process_buy(
    db: &Connection,
    name: &str,
    new_ua: &str,
    signature: &str,
    txid: &str,
    height: u64,
) -> rusqlite::Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute(
        "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, nonce = 0, signature = ?4 WHERE name = ?5",
        rusqlite::params![new_ua, txid, height as i64, signature, name],
    )?;
    tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
    tx.commit()
}

pub fn delete_listing(db: &Connection, name: &str, signature: &str) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE registrations SET signature = ?1 WHERE name = ?2",
        rusqlite::params![signature, name],
    )?;
    db.execute("DELETE FROM listings WHERE name = ?1", [name])?;
    Ok(())
}

pub fn delete_registration(db: &Connection, name: &str) -> rusqlite::Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
    tx.execute("DELETE FROM registrations WHERE name = ?1", [name])?;
    tx.commit()
}

pub fn update_address(
    db: &Connection,
    name: &str,
    new_ua: &str,
    signature: &str,
    txid: &str,
    height: u64,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, signature = ?4 WHERE name = ?5",
        rusqlite::params![new_ua, txid, height as i64, signature, name],
    )?;
    Ok(())
}

pub fn get_owner_ua(db: &Connection, name: &str) -> Option<String> {
    db.query_row(
        "SELECT ua FROM registrations WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .ok()
}

pub fn get_pricing_nonce(db: &Connection) -> Option<u64> {
    db.query_row("SELECT nonce FROM pricing WHERE id = 1", [], |row| {
        Ok(row.get::<_, i64>(0)? as u64)
    })
    .ok()
}

pub fn store_pricing(
    db: &Connection,
    nonce: u64,
    height: u64,
    tiers_json: &str,
    txid: &str,
    signature: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO pricing (id, nonce, tiers, height, txid, signature) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![nonce as i64, tiers_json, height as i64, txid, signature],
    )?;
    Ok(())
}

/// Returns the claim cost in zatoshis for a name of the given length,
/// or None if no pricing has been set yet.
pub fn lookup_claim_cost(db: &Connection, name_len: usize) -> Option<u64> {
    let tiers_str: String = db
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
    db: &Connection,
    name: &str,
    action: &str,
    txid: &str,
    height: u64,
    ua: Option<&str>,
    price: Option<u64>,
    nonce: Option<u64>,
    signature: Option<&str>,
) -> rusqlite::Result<()> {
    db.execute(
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
