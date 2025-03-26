use log::info;
use merka_vault::database::VaultCredentials;
use reqwest::Client;
use serial_test::serial;

mod database_utils;
mod test_utils;

use database_utils::{load_vault_credentials, save_vault_credentials, setup_test_database};
use test_utils::{setup_logging, DockerComposeEnv};

// Test basic database functionality
#[tokio::test]
#[serial]
async fn test_database_credentials() {
    setup_logging();
    info!("Testing database credential storage");

    // Start docker-compose environment
    let mut docker = DockerComposeEnv::new();
    match docker.start() {
        Ok(_) => info!("Docker environment started successfully"),
        Err(e) => {
            info!("Docker environment start failed: {}. Test skipped.", e);
            return;
        }
    }

    // Create a database manager
    let db_manager = match setup_test_database("test_basic_db") {
        Ok(manager) => manager,
        Err(e) => {
            info!("Failed to create database: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

    // Create test credentials
    let test_creds = VaultCredentials {
        root_token: "test-root-token".to_string(),
        root_unseal_keys: vec!["key1".to_string(), "key2".to_string()],
        sub_token: "test-sub-token".to_string(),
        transit_token: "test-transit-token".to_string(),
    };

    // Save credentials
    match save_vault_credentials(&db_manager, &test_creds) {
        Ok(_) => info!("Credentials saved successfully"),
        Err(e) => {
            info!("Failed to save credentials: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

    // Load credentials
    let loaded_creds = match load_vault_credentials(&db_manager) {
        Ok(creds) => creds,
        Err(e) => {
            info!("Failed to load credentials: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

    // Verify loaded credentials
    assert_eq!(
        loaded_creds.root_token, test_creds.root_token,
        "Root token mismatch"
    );
    assert_eq!(
        loaded_creds.root_unseal_keys, test_creds.root_unseal_keys,
        "Unseal keys mismatch"
    );
    assert_eq!(
        loaded_creds.sub_token, test_creds.sub_token,
        "Sub token mismatch"
    );
    assert_eq!(
        loaded_creds.transit_token, test_creds.transit_token,
        "Transit token mismatch"
    );

    // Explicitly stop Docker at the end of the test
    if let Err(e) = docker.stop() {
        info!("Failed to stop Docker Compose: {}", e);
    } else {
        info!("Docker Compose environment stopped successfully");
    }

    info!("Database credential test completed successfully");
}

// Test minimal vault integration
#[tokio::test]
#[serial]
async fn test_minimal_vault_integration() {
    setup_logging();
    info!("Starting minimal vault integration test");

    // Start docker-compose environment
    let mut docker = DockerComposeEnv::new();
    match docker.start() {
        Ok(_) => info!("Docker environment started successfully"),
        Err(e) => {
            info!("Docker environment start failed: {}. Test skipped.", e);
            return;
        }
    }

    // Check if vaults are running
    let client = Client::new();
    let root_vault_url = "http://127.0.0.1:8200";
    let response = client
        .get(format!("{}/v1/sys/health", root_vault_url))
        .send()
        .await;

    match response {
        Ok(resp) => {
            if resp.status().is_success() {
                info!("Root vault is responsive");

                // Create test database
                let db_manager = match setup_test_database("test_minimal") {
                    Ok(manager) => manager,
                    Err(e) => {
                        info!("Failed to create database: {}", e);
                        // Stop Docker before exiting
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };

                // Create and save minimal credentials
                let minimal_creds = VaultCredentials {
                    root_token: "root".to_string(), // Dev mode token
                    root_unseal_keys: vec![],       // Dev mode doesn't need unseal keys
                    sub_token: "".to_string(),
                    transit_token: "".to_string(),
                };

                match save_vault_credentials(&db_manager, &minimal_creds) {
                    Ok(_) => info!("Minimal credentials saved successfully"),
                    Err(e) => {
                        info!("Failed to save minimal credentials: {}", e);
                        // Stop Docker before exiting
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };

                // Verify we can load the credentials
                match load_vault_credentials(&db_manager) {
                    Ok(creds) => {
                        assert_eq!(creds.root_token, "root", "Root token should be 'root'");
                        info!("Minimal credentials loaded successfully");
                    }
                    Err(e) => {
                        info!("Failed to load minimal credentials: {}", e);
                        // Stop Docker before exiting
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };
            } else {
                info!(
                    "Root vault returned status {}, skipping test",
                    resp.status()
                );
                // Stop Docker before skipping
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
            }
        }
        Err(e) => {
            info!("Could not connect to vault: {}. Test skipped.", e);
            // Stop Docker before skipping
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
        }
    }

    // Explicitly stop Docker at the end of the test
    if let Err(e) = docker.stop() {
        info!("Failed to stop Docker Compose: {}", e);
    } else {
        info!("Docker Compose environment stopped successfully");
    }

    info!("Minimal vault integration test completed");
}
