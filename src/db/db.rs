use rusqlite::{params, Connection, Result};

pub struct VaultDb {
    conn: Connection,
}

impl VaultDb {
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vaults (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                root_token TEXT NOT NULL,
                keys TEXT NOT NULL
            )",
            [],
        )?;
        Ok(VaultDb { conn })
    }

    pub fn save_vault(&self, address: &str, root_token: &str, keys: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vaults (address, root_token, keys) VALUES (?1, ?2, ?3)",
            params![address, root_token, keys],
        )?;
        Ok(())
    }

    pub fn get_vault(&self, address: &str) -> Result<Option<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT root_token, keys FROM vaults WHERE address = ?1")?;
        let mut rows = stmt.query(params![address])?;
        if let Some(row) = rows.next()? {
            let root_token: String = row.get(0)?;
            let keys: String = row.get(1)?;
            Ok(Some((root_token, keys)))
        } else {
            Ok(None)
        }
    }
}
