//! Database module for the Merka Vault library
//!
//! This module implements the SQLite-based persistence layer for the Merka Vault library.
//! It is primarily accessed through the actor module, which ensures proper coordination
//! of database operations with vault operations.
//!
//! Architectural role:
//! - Provides persistence for vault credentials and relationships
//! - Should be accessed through the actor module rather than directly
//! - Manages connection pooling and transaction handling

use log::{debug, error, info, warn};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Error as SQLiteError, Result as SQLiteResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// The VaultCredentials struct represents stored vault credentials
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultCredentials {
    // Root vault credentials
    pub root_unseal_keys: Vec<String>,
    pub root_token: String,
    // Sub vault credentials
    pub sub_token: String,
    // Transit token for auto-unseal
    pub transit_token: String,
}

/// Database connection pool type
pub type DbPool = Pool<SqliteConnectionManager>;
pub type DbConnection = PooledConnection<SqliteConnectionManager>;

/// Database manager for merka-vault
#[derive(Clone)]
pub struct DatabaseManager {
    pool: Arc<DbPool>,
}

impl DatabaseManager {
    /// Create a new database manager with the specified database file
    pub fn new(db_path: &str) -> Result<Self, r2d2::Error> {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::new(manager)?;

        // Initialize the database with required tables
        let connection = pool.get()?;
        Self::init_database(&connection).unwrap_or_else(|e| {
            error!("Failed to initialize database: {}", e);
        });

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Initialize the database with required tables
    fn init_database(conn: &DbConnection) -> SQLiteResult<()> {
        // Create tables for vault credentials
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vault_credentials (
                id INTEGER PRIMARY KEY,
                root_unseal_keys TEXT NOT NULL,
                root_token TEXT NOT NULL,
                sub_token TEXT NOT NULL,
                transit_token TEXT NOT NULL
            )",
            [],
        )?;

        // Create table for vault relationships (unsealer relationships)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vault_relationships (
                id INTEGER PRIMARY KEY,
                sub_addr TEXT NOT NULL UNIQUE,
                root_addr TEXT NOT NULL
            )",
            [],
        )?;

        info!("Database initialized successfully");
        Ok(())
    }

    /// Save vault credentials to the database
    pub fn save_vault_credentials(&self, credentials: &VaultCredentials) -> SQLiteResult<()> {
        let conn = self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            SQLiteError::ExecuteReturnedResults
        })?;

        // Serialize the root_unseal_keys vector to JSON
        let root_unseal_keys =
            serde_json::to_string(&credentials.root_unseal_keys).map_err(|e| {
                error!("Failed to serialize root_unseal_keys: {}", e);
                SQLiteError::ExecuteReturnedResults
            })?;

        // Check if credentials already exist
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM vault_credentials", [], |row| {
            row.get(0)
        })?;

        if count > 0 {
            // Update existing credentials
            conn.execute(
                "UPDATE vault_credentials SET
                    root_unseal_keys = ?,
                    root_token = ?,
                    sub_token = ?,
                    transit_token = ?
                WHERE id = 1",
                params![
                    root_unseal_keys,
                    credentials.root_token,
                    credentials.sub_token,
                    credentials.transit_token
                ],
            )?;
            debug!("Updated existing vault credentials in database");
        } else {
            // Insert new credentials
            conn.execute(
                "INSERT INTO vault_credentials (
                    root_unseal_keys, root_token, sub_token, transit_token
                ) VALUES (?, ?, ?, ?)",
                params![
                    root_unseal_keys,
                    credentials.root_token,
                    credentials.sub_token,
                    credentials.transit_token
                ],
            )?;
            debug!("Inserted new vault credentials into database");
        }

        info!("✅ Vault credentials successfully saved to database");
        info!("  Root token length: {}", credentials.root_token.len());
        info!("  Root unseal keys: {}", credentials.root_unseal_keys.len());
        info!("  Sub token length: {}", credentials.sub_token.len());
        info!(
            "  Transit token length: {}",
            credentials.transit_token.len()
        );

        Ok(())
    }

    /// Load vault credentials from the database
    pub fn load_vault_credentials(&self) -> SQLiteResult<VaultCredentials> {
        let conn = self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            SQLiteError::ExecuteReturnedResults
        })?;

        let result = conn.query_row(
            "SELECT root_unseal_keys, root_token, sub_token, transit_token FROM vault_credentials LIMIT 1",
            [],
            |row| {
                let root_unseal_keys_json: String = row.get(0)?;

                // Deserialize the root_unseal_keys JSON back to vector
                let root_unseal_keys: Vec<String> = serde_json::from_str(&root_unseal_keys_json)
                    .map_err(|e| {
                        error!("Failed to deserialize root_unseal_keys: {}", e);
                        SQLiteError::ExecuteReturnedResults
                    })?;

                Ok(VaultCredentials {
                    root_unseal_keys,
                    root_token: row.get(1)?,
                    sub_token: row.get(2)?,
                    transit_token: row.get(3)?,
                })
            },
        );

        match result {
            Ok(credentials) => {
                info!("Loaded vault credentials from database");
                info!("  Root token length: {}", credentials.root_token.len());
                info!("  Root unseal keys: {}", credentials.root_unseal_keys.len());
                info!("  Sub token length: {}", credentials.sub_token.len());
                info!(
                    "  Transit token length: {}",
                    credentials.transit_token.len()
                );

                Ok(credentials)
            }
            Err(e) => {
                warn!("Failed to load vault credentials from database: {}", e);

                // Return default credentials when none exist
                if e == SQLiteError::QueryReturnedNoRows {
                    warn!("No credentials found in database, returning default");
                    return Ok(VaultCredentials::default());
                }

                Err(e)
            }
        }
    }

    /// Save an unsealer relationship to the database
    pub fn save_unsealer_relationship(&self, sub_addr: &str, root_addr: &str) -> SQLiteResult<()> {
        let conn = self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            SQLiteError::ExecuteReturnedResults
        })?;

        // Use insert or replace to handle updates
        conn.execute(
            "INSERT OR REPLACE INTO vault_relationships (sub_addr, root_addr) VALUES (?, ?)",
            params![sub_addr, root_addr],
        )?;

        info!(
            "Saved unsealer relationship: sub={}, root={}",
            sub_addr, root_addr
        );

        Ok(())
    }

    /// Load all unsealer relationships from the database
    pub fn load_unsealer_relationships(&self) -> SQLiteResult<HashMap<String, String>> {
        let conn = self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            SQLiteError::ExecuteReturnedResults
        })?;

        let mut stmt = conn.prepare("SELECT sub_addr, root_addr FROM vault_relationships")?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut relationships = HashMap::new();
        for row_result in rows {
            match row_result {
                Ok((sub_addr, root_addr)) => {
                    relationships.insert(sub_addr, root_addr);
                }
                Err(e) => {
                    warn!("Error reading relationship row: {}", e);
                }
            }
        }

        info!(
            "Loaded {} unsealer relationships from database",
            relationships.len()
        );
        Ok(relationships)
    }

    /// Delete an unsealer relationship from the database
    pub fn delete_unsealer_relationship(&self, sub_addr: &str) -> SQLiteResult<()> {
        let conn = self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            SQLiteError::ExecuteReturnedResults
        })?;

        conn.execute(
            "DELETE FROM vault_relationships WHERE sub_addr = ?",
            params![sub_addr],
        )?;

        info!("Deleted unsealer relationship for sub={}", sub_addr);
        Ok(())
    }

    /// Get pool for use in the application
    pub fn get_pool(&self) -> Arc<DbPool> {
        self.pool.clone()
    }
}
