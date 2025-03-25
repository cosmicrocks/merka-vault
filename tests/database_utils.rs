use log::{error, info, warn};
use merka_vault::database::{DatabaseManager, VaultCredentials};
use std::io;

/// Saves vault credentials to a test database
pub fn save_vault_credentials(
    db_manager: &DatabaseManager,
    credentials: &VaultCredentials,
) -> Result<(), io::Error> {
    // Validate credentials before saving
    if credentials.root_token.is_empty() {
        warn!("Root token is empty, but saving credentials anyway");
    }

    // Save credentials to database
    match db_manager.save_vault_credentials(credentials) {
        Ok(_) => {
            // Log the saved data to help with debugging
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
        Err(e) => {
            error!("Failed to save credentials to database: {}", e);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Database error: {}", e),
            ))
        }
    }
}

/// Loads vault credentials from a test database
pub fn load_vault_credentials(db_manager: &DatabaseManager) -> Result<VaultCredentials, io::Error> {
    // Load credentials from database
    match db_manager.load_vault_credentials() {
        Ok(credentials) => {
            // Log the loaded data
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
            warn!("Failed to load credentials from database: {}", e);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Database error: {}", e),
            ))
        }
    }
}

/// Sets up a test database with a unique path
pub fn setup_test_database(db_name: &str) -> Result<DatabaseManager, io::Error> {
    let db_path = format!("{}.db", db_name);

    // Clean up any existing test DB
    let _ = std::fs::remove_file(&db_path);

    // Create database manager
    DatabaseManager::new(&db_path).map_err(|e| {
        error!("Failed to create database manager: {}", e);
        io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e))
    })
}
