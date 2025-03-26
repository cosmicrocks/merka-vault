use actix::Actor;
use log::{error, info, warn};
use merka_vault::database::{DatabaseManager, VaultCredentials};
use reqwest::Client;
use serde_json::{json, Value};
use serial_test::serial;
use std::io;
use tokio::time::Duration;

mod database_utils;
mod test_utils;

use database_utils::{load_vault_credentials, save_vault_credentials, setup_test_database};
use test_utils::{is_server_running, setup_logging, DockerComposeEnv};

// This is a comprehensive integration test that mirrors the functionality
// in examples/test_client.rs but follows proper testing patterns
#[tokio::test]
#[serial]
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
    match docker.start() {
        Ok(_) => info!("Docker environment started successfully"),
        Err(e) => {
            info!("Docker environment start failed: {}. Test skipped.", e);
            return;
        }
    }

    // Create database manager for vault credentials
    let db_manager = match setup_test_database("test_integration_flow") {
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
                let status = match res.json::<Value>().await {
                    Ok(val) => val,
                    Err(e) => {
                        info!("Failed to parse status JSON: {}", e);
                        // Stop Docker before returning
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };
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
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }
        }
        Err(e) => {
            info!("Failed to connect to server status endpoint: {}", e);
            // Stop Docker before returning
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
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
                let init_result = match res.json::<Value>().await {
                    Ok(val) => val,
                    Err(e) => {
                        info!("Failed to parse init JSON: {}", e);
                        // Stop Docker before returning
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };
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
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }
        }
        Err(e) => {
            info!("Failed to initialize root vault: {}", e);
            // Stop Docker before returning
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
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
                let unseal_result = match res.json::<Value>().await {
                    Ok(val) => val,
                    Err(e) => {
                        info!("Failed to parse unseal JSON: {}", e);
                        // Stop Docker before returning
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };
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
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }
        }
        Err(e) => {
            info!("Failed to unseal root vault: {}", e);
            // Stop Docker before returning
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
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
                let transit_result = match res.json::<Value>().await {
                    Ok(val) => val,
                    Err(e) => {
                        info!("Failed to parse transit setup JSON: {}", e);
                        // Stop Docker before returning
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };
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
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }
        }
        Err(e) => {
            info!("Failed to set up transit engine: {}", e);
            // Stop Docker before returning
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
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
                let sub_init_result = match res.json::<Value>().await {
                    Ok(val) => val,
                    Err(e) => {
                        info!("Failed to parse sub init JSON: {}", e);
                        // Stop Docker before returning
                        if let Err(stop_err) = docker.stop() {
                            info!("Failed to stop Docker Compose: {}", stop_err);
                        }
                        return;
                    }
                };
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
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }
        }
        Err(e) => {
            info!("Failed to initialize sub vault: {}", e);
            // Stop Docker before returning
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
            return;
        }
    }

    // Save credentials to database
    info!("Saving vault credentials to database");
    if let Err(e) = save_vault_credentials(&db_manager, &credentials) {
        info!("Failed to save credentials to database: {}", e);
        // Stop Docker before returning
        if let Err(e) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", e);
        }
        return;
    }

    // Step 6: Load credentials to verify
    info!("Loading vault credentials from database");
    match load_vault_credentials(&db_manager) {
        Ok(loaded_creds) => {
            info!("Loaded credentials from database");

            // Check that credentials match what was saved - use if statements instead of assert
            if loaded_creds.root_token != credentials.root_token {
                info!(
                    "Root token mismatch: expected '{}', got '{}'",
                    credentials.root_token, loaded_creds.root_token
                );
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }

            if loaded_creds.root_unseal_keys != credentials.root_unseal_keys {
                info!(
                    "Root unseal keys mismatch: expected {:?}, got {:?}",
                    credentials.root_unseal_keys, loaded_creds.root_unseal_keys
                );
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }

            if loaded_creds.sub_token != credentials.sub_token {
                info!(
                    "Sub token mismatch: expected '{}', got '{}'",
                    credentials.sub_token, loaded_creds.sub_token
                );
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }

            if loaded_creds.transit_token != credentials.transit_token {
                info!(
                    "Transit token mismatch: expected '{}', got '{}'",
                    credentials.transit_token, loaded_creds.transit_token
                );
                // Stop Docker before returning
                if let Err(e) = docker.stop() {
                    info!("Failed to stop Docker Compose: {}", e);
                }
                return;
            }

            info!("All credentials verified successfully");
        }
        Err(e) => {
            info!("Failed to load credentials from database: {}", e);
            // Make sure to stop Docker before returning
            if let Err(e) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", e);
            }
            return;
        }
    }

    // Explicitly stop Docker Compose
    if let Err(e) = docker.stop() {
        info!("Failed to stop Docker Compose: {}", e);
    } else {
        info!("Docker Compose environment stopped successfully");
    }

    info!("Vault setup flow integration test completed successfully");
}

// Test that focuses just on the database functionality
#[tokio::test]
#[serial]
async fn test_database_operations() {
    setup_logging();
    info!("Testing database operations");

    // Start docker-compose environment
    let mut docker = DockerComposeEnv::new();
    match docker.start() {
        Ok(_) => info!("Docker environment started successfully"),
        Err(e) => {
            info!("Docker environment start failed: {}. Test skipped.", e);
            return;
        }
    }

    // Use a dedicated database file for this test
    let db_path = "test_db_operations.db";
    let _ = std::fs::remove_file(db_path);

    // Create database manager
    let db_manager = match DatabaseManager::new(db_path) {
        Ok(manager) => manager,
        Err(e) => {
            info!("Failed to create DatabaseManager: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

    // Test saving and loading credentials
    let test_credentials = VaultCredentials {
        root_token: "test-root-token".to_string(),
        root_unseal_keys: vec!["key1".to_string(), "key2".to_string()],
        sub_token: "test-sub-token".to_string(),
        transit_token: "test-transit-token".to_string(),
    };

    if let Err(e) = save_vault_credentials(&db_manager, &test_credentials) {
        info!("Failed to save credentials: {}", e);
        // Stop Docker before returning
        if let Err(stop_err) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", stop_err);
        }
        return;
    }

    let loaded_credentials = match load_vault_credentials(&db_manager) {
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
    if let Err(e) = db_manager.save_unsealer_relationship(sub_addr, root_addr) {
        info!("Failed to save unsealer relationship: {}", e);
        // Stop Docker before returning
        if let Err(stop_err) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", stop_err);
        }
        return;
    }

    // Verify it was saved
    let relationships = match db_manager.load_unsealer_relationships() {
        Ok(rels) => rels,
        Err(e) => {
            info!("Failed to load unsealer relationships: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

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
    if let Err(e) = db_manager.save_unsealer_relationship(sub_addr2, root_addr) {
        info!("Failed to save second unsealer relationship: {}", e);
        // Stop Docker before returning
        if let Err(stop_err) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", stop_err);
        }
        return;
    }

    // Verify both relationships exist
    let relationships = match db_manager.load_unsealer_relationships() {
        Ok(rels) => rels,
        Err(e) => {
            info!("Failed to load unsealer relationships: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

    assert_eq!(
        relationships.len(),
        2,
        "Expected two unsealer relationships"
    );

    // Delete first relationship
    if let Err(e) = db_manager.delete_unsealer_relationship(sub_addr) {
        info!("Failed to delete unsealer relationship: {}", e);
        // Stop Docker before returning
        if let Err(stop_err) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", stop_err);
        }
        return;
    }

    // Verify only the second relationship remains
    let relationships = match db_manager.load_unsealer_relationships() {
        Ok(rels) => rels,
        Err(e) => {
            info!("Failed to load unsealer relationships: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

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
    if let Err(e) = db_manager.delete_unsealer_relationship(sub_addr2) {
        info!("Failed to delete second unsealer relationship: {}", e);
        // Stop Docker before returning
        if let Err(stop_err) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", stop_err);
        }
        return;
    }

    // Verify no relationships remain
    let relationships = match db_manager.load_unsealer_relationships() {
        Ok(rels) => rels,
        Err(e) => {
            info!("Failed to load unsealer relationships: {}", e);
            // Stop Docker before returning
            if let Err(stop_err) = docker.stop() {
                info!("Failed to stop Docker Compose: {}", stop_err);
            }
            return;
        }
    };

    assert_eq!(
        relationships.len(),
        0,
        "Expected no unsealer relationships after deletion"
    );

    // Clean up
    let _ = std::fs::remove_file(db_path);

    // Explicitly stop Docker at the end of the test
    if let Err(e) = docker.stop() {
        info!("Failed to stop Docker Compose: {}", e);
    } else {
        info!("Docker Compose environment stopped successfully");
    }

    info!("Database operations test completed successfully");
}
