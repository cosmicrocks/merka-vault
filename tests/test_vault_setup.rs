use actix::Actor;
use log::{error, info, warn};
use merka_vault::database::{DatabaseManager, VaultCredentials};
use reqwest::Client;
use serde_json::{json, Value};
use std::io;
use std::{env, process::Command};
use tokio::time::Duration;

mod database_utils;
mod test_utils;

use database_utils::{load_vault_credentials, save_vault_credentials, setup_test_database};
use test_utils::{setup_logging, DockerComposeEnv};

// Test basic database functionality
#[tokio::test]
async fn test_database_credentials() {
    setup_logging();
    info!("Testing database credential storage");

    // Create a database manager
    let db_manager = match setup_test_database("test_basic_db") {
        Ok(manager) => manager,
        Err(e) => {
            panic!("Failed to create database: {}", e);
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
        Err(e) => panic!("Failed to save credentials: {}", e),
    };

    // Load credentials
    let loaded_creds = match load_vault_credentials(&db_manager) {
        Ok(creds) => creds,
        Err(e) => panic!("Failed to load credentials: {}", e),
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

    info!("Database credential test completed successfully");
}

// Test minimal vault integration
#[tokio::test]
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
        .get(&format!("{}/v1/sys/health", root_vault_url))
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
                        panic!("Failed to create database: {}", e);
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
                    Err(e) => panic!("Failed to save minimal credentials: {}", e),
                };

                // Verify we can load the credentials
                match load_vault_credentials(&db_manager) {
                    Ok(creds) => {
                        assert_eq!(creds.root_token, "root", "Root token should be 'root'");
                        info!("Minimal credentials loaded successfully");
                    }
                    Err(e) => panic!("Failed to load minimal credentials: {}", e),
                };
            } else {
                info!(
                    "Root vault returned status {}, skipping test",
                    resp.status()
                );
            }
        }
        Err(e) => {
            info!("Could not connect to vault: {}. Test skipped.", e);
        }
    }

    info!("Minimal vault integration test completed");
}
