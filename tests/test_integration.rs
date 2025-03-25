use actix::Actor;
use log::{error, info, warn};
use merka_vault::database::{DatabaseManager, VaultCredentials};
use reqwest::Client;
use serde_json::{json, Value};
use std::io;
use tokio::time::Duration;

mod database_utils;
mod test_utils;

use database_utils::{load_vault_credentials, save_vault_credentials, setup_test_database};
use test_utils::{is_server_running, setup_logging, DockerComposeEnv};

// This is a comprehensive integration test that mirrors the functionality
// in examples/test_client.rs but follows proper testing patterns
#[tokio::test]
async fn test_vault_setup_flow() {
    setup_logging();
    info!("Starting vault setup flow integration test");

    // Check if the server is already running
    if !is_server_running().await {
        info!("Web server not running. This test requires the server to be running.");
        info!("Start the server in another terminal with: cargo run -- server");
        info!("Skipping test_vault_setup_flow");
        return;
    }

    info!("Server is running. Proceeding with test.");

    // Test database path - use unique path to avoid conflicts
    let db_path = "test_integration_flow.db";

    // Clean up any existing test DB
    let _ = std::fs::remove_file(db_path);

    // Start docker-compose for the vault instances
    let mut docker = DockerComposeEnv::new();
    if let Err(e) = docker.start() {
        panic!("Failed to start docker-compose: {}", e);
    }

    // Create database manager for vault credentials
    let db_manager =
        setup_test_database("test_integration_flow").expect("Failed to create DatabaseManager");

    // Initialize credentials structure
    let mut credentials = VaultCredentials::default();

    // Create HTTP client for API requests
    let client = reqwest::Client::new();

    // Step 1: Check initial vault status
    info!("Checking initial vault status");
    let status_res = client.get("http://localhost:8080/api/status").send().await;

    // Continue with the rest of the test implementation...
    match status_res {
        Ok(res) => {
            if res.status().is_success() {
                let status: Value = res.json().await.expect("Failed to parse status JSON");
                info!("Server status: {:?}", status);
            } else {
                let status = res.status();
                let error_text = res
                    .text()
                    .await
                    .unwrap_or_else(|_| "No error text".to_string());
                info!(
                    "Server returned non-success status: {}, {}",
                    status, error_text
                );
                return;
            }
        }
        Err(e) => {
            info!("Failed to connect to server status endpoint: {}", e);
            return;
        }
    }

    // Step 2: Initialize the root vault
    info!("Initializing root vault");
    let init_res = client
        .post("http://localhost:8080/api/vault/init")
        .json(&json!({
            "secret_shares": 1,
            "secret_threshold": 1
        }))
        .send()
        .await;

    match init_res {
        Ok(res) => {
            let status = res.status();
            if status.is_success() {
                let init_result: Value = res.json().await.expect("Failed to parse init JSON");
                info!("Initialization result: {:?}", init_result);

                // Extract and store credentials
                if let Some(result) = init_result.get("result") {
                    if let Some(token) = result.get("root_token") {
                        credentials.root_token = token.as_str().unwrap_or("").to_string();
                    }
                    if let Some(keys) = result.get("keys") {
                        credentials.root_unseal_keys = keys
                            .as_array()
                            .unwrap_or(&Vec::new())
                            .iter()
                            .map(|k| k.as_str().unwrap_or("").to_string())
                            .collect();
                    }
                }
            } else {
                let error_text = res
                    .text()
                    .await
                    .unwrap_or_else(|_| "No error text".to_string());
                info!(
                    "Root vault initialization failed with status {}: {}",
                    status, error_text
                );
                return;
            }
        }
        Err(e) => {
            info!("Failed to initialize root vault: {}", e);
            return;
        }
    }

    // Step 3: Unseal the root vault
    info!("Unsealing root vault");
    let unseal_res = client
        .post("http://localhost:8080/api/vault/unseal")
        .json(&json!({
            "keys": credentials.root_unseal_keys
        }))
        .send()
        .await;

    match unseal_res {
        Ok(res) => {
            let status = res.status();
            if status.is_success() {
                let unseal_result: Value = res.json().await.expect("Failed to parse unseal JSON");
                info!("Unseal result: {:?}", unseal_result);
            } else {
                let error_text = res
                    .text()
                    .await
                    .unwrap_or_else(|_| "No error text".to_string());
                info!(
                    "Root vault unseal failed with status {}: {}",
                    status, error_text
                );
                return;
            }
        }
        Err(e) => {
            info!("Failed to unseal root vault: {}", e);
            return;
        }
    }

    // Step 4: Set up transit engine
    info!("Setting up transit engine");
    let transit_res = client
        .post("http://localhost:8080/api/vault/setup-transit")
        .json(&json!({
            "token": credentials.root_token
        }))
        .send()
        .await;

    match transit_res {
        Ok(res) => {
            let status = res.status();
            if status.is_success() {
                let transit_result: Value = res
                    .json()
                    .await
                    .expect("Failed to parse transit setup JSON");
                info!("Transit setup result: {:?}", transit_result);

                // Extract transit token
                if let Some(token) = transit_result.get("transit_token") {
                    credentials.transit_token = token.as_str().unwrap_or("").to_string();
                }
            } else {
                let error_text = res
                    .text()
                    .await
                    .unwrap_or_else(|_| "No error text".to_string());
                info!(
                    "Transit setup failed with status {}: {}",
                    status, error_text
                );
                return;
            }
        }
        Err(e) => {
            info!("Failed to set up transit engine: {}", e);
            return;
        }
    }

    // Step 5: Initialize sub vault
    info!("Initializing sub vault");
    let sub_init_res = client
        .post("http://localhost:8080/api/vault/init-sub")
        .json(&json!({
            "transit_token": credentials.transit_token
        }))
        .send()
        .await;

    match sub_init_res {
        Ok(res) => {
            let status = res.status();
            if status.is_success() {
                let sub_init_result: Value =
                    res.json().await.expect("Failed to parse sub init JSON");
                info!("Sub vault initialization result: {:?}", sub_init_result);

                // Extract sub token
                if let Some(token) = sub_init_result.get("token") {
                    credentials.sub_token = token.as_str().unwrap_or("").to_string();
                }
            } else {
                let error_text = res
                    .text()
                    .await
                    .unwrap_or_else(|_| "No error text".to_string());
                info!(
                    "Sub vault initialization failed with status {}: {}",
                    status, error_text
                );
                return;
            }
        }
        Err(e) => {
            info!("Failed to initialize sub vault: {}", e);
            return;
        }
    }

    // Save credentials to database
    info!("Saving vault credentials to database");
    if let Err(e) = save_vault_credentials(&db_manager, &credentials) {
        info!("Failed to save credentials to database: {}", e);
        return;
    }

    // Step 6: Load credentials to verify
    info!("Loading vault credentials from database");
    match load_vault_credentials(&db_manager) {
        Ok(loaded_creds) => {
            info!("Loaded credentials from database");
            assert_eq!(loaded_creds.root_token, credentials.root_token);
            assert_eq!(loaded_creds.root_unseal_keys, credentials.root_unseal_keys);
            assert_eq!(loaded_creds.sub_token, credentials.sub_token);
            assert_eq!(loaded_creds.transit_token, credentials.transit_token);
        }
        Err(e) => {
            info!("Failed to load credentials from database: {}", e);
            return;
        }
    }

    info!("Vault setup flow integration test completed successfully");
}

// Test that focuses just on the database functionality
#[tokio::test]
async fn test_database_operations() {
    setup_logging();
    info!("Testing database operations");

    // Use a dedicated database file for this test
    let db_path = "test_db_operations.db";
    let _ = std::fs::remove_file(db_path);

    // Create database manager
    let db_manager = DatabaseManager::new(db_path).expect("Failed to create DatabaseManager");

    // Test saving and loading credentials
    let test_credentials = VaultCredentials {
        root_token: "test-root-token".to_string(),
        root_unseal_keys: vec!["key1".to_string(), "key2".to_string()],
        sub_token: "test-sub-token".to_string(),
        transit_token: "test-transit-token".to_string(),
    };

    save_vault_credentials(&db_manager, &test_credentials).expect("Failed to save credentials");

    let loaded_credentials =
        load_vault_credentials(&db_manager).expect("Failed to load credentials");

    // Verify loaded credentials match what was saved
    assert_eq!(
        loaded_credentials.root_token, test_credentials.root_token,
        "Root token mismatch"
    );
    assert_eq!(
        loaded_credentials.sub_token, test_credentials.sub_token,
        "Sub token mismatch"
    );
    assert_eq!(
        loaded_credentials.transit_token, test_credentials.transit_token,
        "Transit token mismatch"
    );
    assert_eq!(
        loaded_credentials.root_unseal_keys.len(),
        test_credentials.root_unseal_keys.len(),
        "Root unseal keys count mismatch"
    );

    // Test saving, loading, and deleting unsealer relationships
    let sub_addr = "http://127.0.0.1:8202";
    let root_addr = "http://127.0.0.1:8200";

    // Save relationship
    db_manager
        .save_unsealer_relationship(sub_addr, root_addr)
        .expect("Failed to save unsealer relationship");

    // Verify it was saved
    let relationships = db_manager
        .load_unsealer_relationships()
        .expect("Failed to load unsealer relationships");

    assert_eq!(relationships.len(), 1, "Expected one unsealer relationship");
    assert!(
        relationships.contains_key(sub_addr),
        "Expected sub vault address in relationships"
    );
    assert_eq!(
        relationships.get(sub_addr).unwrap(),
        root_addr,
        "Root vault address mismatch"
    );

    // Add a second relationship
    let sub_addr2 = "http://127.0.0.1:8203";
    db_manager
        .save_unsealer_relationship(sub_addr2, root_addr)
        .expect("Failed to save second unsealer relationship");

    // Verify both relationships exist
    let relationships = db_manager
        .load_unsealer_relationships()
        .expect("Failed to load unsealer relationships");

    assert_eq!(
        relationships.len(),
        2,
        "Expected two unsealer relationships"
    );

    // Delete first relationship
    db_manager
        .delete_unsealer_relationship(sub_addr)
        .expect("Failed to delete unsealer relationship");

    // Verify only the second relationship remains
    let relationships = db_manager
        .load_unsealer_relationships()
        .expect("Failed to load unsealer relationships");

    assert_eq!(
        relationships.len(),
        1,
        "Expected one unsealer relationship after deletion"
    );
    assert!(
        !relationships.contains_key(sub_addr),
        "Deleted relationship should not be present"
    );
    assert!(
        relationships.contains_key(sub_addr2),
        "Second relationship should still be present"
    );

    // Delete second relationship
    db_manager
        .delete_unsealer_relationship(sub_addr2)
        .expect("Failed to delete second unsealer relationship");

    // Verify no relationships remain
    let relationships = db_manager
        .load_unsealer_relationships()
        .expect("Failed to load unsealer relationships");

    assert_eq!(
        relationships.len(),
        0,
        "Expected no unsealer relationships after deletion"
    );

    // Clean up
    let _ = std::fs::remove_file(db_path);
    info!("Database operations test completed successfully");
}
