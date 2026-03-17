// ZNS registry — SQLite storage for name registrations and marketplace listings.

use rusqlite::Connection;

/// Listing price in zats.
pub type Listing = u64;

/// Opens (or creates) the registry database and ensures the schema exists.
pub fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL UNIQUE,
            txid    TEXT NOT NULL,
            height  INTEGER NOT NULL,
            nonce   INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS listings (
            name    TEXT PRIMARY KEY REFERENCES registrations(name),
            price   INTEGER NOT NULL,
            txid    TEXT NOT NULL,
            height  INTEGER NOT NULL
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

pub fn get_nonce(db: &Connection, name: &str) -> Option<u64> {
    db.query_row(
        "SELECT nonce FROM registrations WHERE name = ?1",
        [name],
        |row| Ok(row.get::<_, i64>(0)? as u64),
    )
    .ok()
}

pub fn increment_nonce(db: &Connection, name: &str, new_nonce: u64) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE registrations SET nonce = ?1 WHERE name = ?2",
        rusqlite::params![new_nonce as i64, name],
    )?;
    Ok(())
}

/// Returns true if a new row was actually inserted.
pub fn create_registration(
    db: &Connection,
    name: &str,
    ua: &str,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<bool> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    db.execute(
        "INSERT OR IGNORE INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, ua, txid_hex, height as i64],
    )?;
    Ok(db.changes() > 0)
}

pub fn create_listing(
    db: &Connection,
    name: &str,
    price: u64,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<()> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    db.execute(
        "INSERT OR REPLACE INTO listings (name, price, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, price as i64, txid_hex, height as i64],
    )?;
    Ok(())
}

pub fn get_listing(db: &Connection, name: &str) -> Option<Listing> {
    db.query_row(
        "SELECT price FROM listings WHERE name = ?1",
        [name],
        |row| Ok(row.get::<_, i64>(0)? as Listing),
    )
    .ok()
}

pub fn process_buy(
    db: &Connection,
    name: &str,
    new_ua: &str,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<()> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    let tx = db.unchecked_transaction()?;
    tx.execute(
        "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3, nonce = 0 WHERE name = ?4",
        rusqlite::params![new_ua, txid_hex, height as i64, name],
    )?;
    tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
    tx.commit()
}

pub fn delete_listing(db: &Connection, name: &str) -> rusqlite::Result<()> {
    db.execute("DELETE FROM listings WHERE name = ?1", [name])?;
    Ok(())
}

pub fn update_address(
    db: &Connection,
    name: &str,
    new_ua: &str,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<()> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    db.execute(
        "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3 WHERE name = ?4",
        rusqlite::params![new_ua, txid_hex, height as i64, name],
    )?;
    Ok(())
}
