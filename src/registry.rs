// ZNS registry — SQLite write path for the indexer.

use rusqlite::Connection;

/// Opens (or creates) the registry database and ensures the schema exists.
pub fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name      TEXT PRIMARY KEY,
            ua        TEXT NOT NULL UNIQUE,
            txid      TEXT NOT NULL,
            height    INTEGER NOT NULL,
            nonce     INTEGER NOT NULL DEFAULT 0,
            signature TEXT
        );
        CREATE TABLE IF NOT EXISTS listings (
            name      TEXT PRIMARY KEY REFERENCES registrations(name),
            price     INTEGER NOT NULL,
            txid      TEXT NOT NULL,
            height    INTEGER NOT NULL,
            signature TEXT NOT NULL
        );",
    )?;
    Ok(conn)
}

pub fn is_registered(db: &Connection, name: &str, ua: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM registrations WHERE name = ?1 OR ua = ?2",
        rusqlite::params![name, ua],
        |_| Ok(()),
    )
    .is_ok()
}

pub fn validate_and_increment_nonce(db: &Connection, name: &str, nonce: u64) -> Result<(), String> {
    let current: u64 = db.query_row(
        "SELECT nonce FROM registrations WHERE name = ?1",
        [name],
        |row| Ok(row.get::<_, i64>(0)? as u64),
    ).map_err(|_| format!("unregistered name {name}"))?;
    if nonce <= current {
        return Err(format!("replay rejected for {name}: nonce {nonce} <= {current}"));
    }
    db.execute(
        "UPDATE registrations SET nonce = ?1 WHERE name = ?2",
        rusqlite::params![nonce as i64, name],
    ).map_err(|e| format!("DB error (nonce): {e}"))?;
    Ok(())
}

/// Returns true if a new row was actually inserted.
pub fn create_registration(
    db: &Connection,
    name: &str,
    ua: &str,
    txid: &str,
    height: u64,
) -> rusqlite::Result<bool> {
    db.execute(
        "INSERT OR IGNORE INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, ua, txid, height as i64],
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
    txid: &str,
    height: u64,
) -> rusqlite::Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute(
        "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, nonce = 0 WHERE name = ?4",
        rusqlite::params![new_ua, txid, height as i64, name],
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
