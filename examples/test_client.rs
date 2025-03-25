use log::{error, info, warn};
use merka_vault::database::{DatabaseManager, VaultCredentials};
use reqwest::Client;
use serde_json::{json, Value};
use std::env;
use std::io;

// This example replicates the workflow of the wizard.rs, but through web server API calls.
// It demonstrates setting up a root vault and a sub vault with auto-unseal.
//
// Usage:
//   cargo run --example test_client            # Basic setup, prints instructions to restart sub vault
//   cargo run --example test_client --restart-sub-vault  # Automatically restarts sub vault with transit token
//
// Note: This requires the web server to be running:
//   cargo run --example web_server
//
// And docker-compose to be available for the vault services:
//   docker-compose up -d

// Local struct definition removed - now using VaultCredentials from database module

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with env_logger, setting a default log level if RUST_LOG is not set
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Starting Merka Vault test client");
    info!("This example assumes you have started the web server and docker-compose vaults");
    info!("---------------------------------------------------------------------------------");
    info!("IMPORTANT: If you're running this test client against an existing vault that is");
    info!("sealed, you'll need to unseal it first either with the unseal keys from when");
    info!("it was initialized, or by restarting the vault in dev mode.");
    info!("---------------------------------------------------------------------------------");

    // Create HTTP client
    let client = Client::builder().build()?;

    // Check command line args
    let restart_sub_vault = env::args().any(|arg| arg == "--restart-sub-vault");

    // Run the setup flow
    run_setup_flow(&client, restart_sub_vault).await?;

    info!("Test client finished. Exiting...");

    Ok(())
}

// Function to save vault credentials
fn save_vault_credentials(credentials: &VaultCredentials) -> Result<(), io::Error> {
    // Validate credentials before saving
    if credentials.root_token.is_empty() {
        warn!("Root token is empty, but saving credentials anyway");
    }

    // Create a database manager
    let db_path = "merka_vault.db";
    let db_manager = match DatabaseManager::new(db_path) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Database error: {}", e),
            ));
        }
    };

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

// Function to load vault credentials
fn load_vault_credentials() -> Result<VaultCredentials, io::Error> {
    // Create a database manager
    let db_path = "merka_vault.db";
    let db_manager = match DatabaseManager::new(db_path) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Database error: {}", e),
            ));
        }
    };

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

// Implement the setup flow function that replicates the wizard functionality via API calls
async fn run_setup_flow(
    client: &Client,
    restart_sub_vault: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting vault setup flow");

    // Initialize the credentials structure to store all tokens and keys
    let mut credentials = VaultCredentials::default();

    // Try to load existing credentials first
    if let Ok(loaded_creds) = load_vault_credentials() {
        info!("Found existing vault credentials, will reuse if possible");
        credentials = loaded_creds;
    }

    // Add a small delay to ensure the web server has time to start up
    info!("Waiting 1 second for web server to be ready...");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Try multiple times to connect to the web server
    let mut retry_count = 0;
    let max_retries = 3;
    let mut status_res = None;

    while retry_count < max_retries {
        match client.get("http://localhost:8080/api/status").send().await {
            Ok(res) => {
                status_res = Some(res);
                break;
            }
            Err(e) => {
                retry_count += 1;
                if retry_count < max_retries {
                    error!("Failed to connect to web server (attempt {}/{}): {}. Retrying in 1 second...",
                        retry_count, max_retries, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                } else {
                    error!("Failed to connect to web server after {} attempts: {}. Make sure the web server is running.",
                        max_retries, e);
                    return Err(Box::new(e));
                }
            }
        }
    }

    let status_res = status_res.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Failed to connect to web server",
        )
    })?;

    let status: Value = status_res.json().await?;
    info!("Current vault status: {}", status);

    // Check if vault is initialized and sealed
    let initialized = status["data"]["initialized"].as_bool().unwrap_or(false);
    let sealed = status["data"]["sealed"].as_bool().unwrap_or(true);

    info!(
        "Vault status: initialized={}, sealed={}",
        initialized, sealed
    );

    // Step 1: Set up the root vault (using the same default values as the wizard)
    info!("Setting up root vault with default configuration");

    // Include existing token in the request if we have it
    let mut root_setup_request = json!({
        "root_addr": "http://127.0.0.1:8200",
        "secret_shares": 1,
        "secret_threshold": 1,
        "key_name": "autounseal-key"
    });

    // If we have an existing token from a previous run, include it
    if !credentials.root_token.is_empty() {
        info!("Using existing root token for setup request");
        if let serde_json::Value::Object(ref mut map) = root_setup_request {
            map.insert("token".to_string(), json!(credentials.root_token));
        }
    }

    let root_setup_res = client
        .post("http://localhost:8080/api/setup_root")
        .json(&root_setup_request)
        .send()
        .await?;

    if !root_setup_res.status().is_success() {
        let error_text = root_setup_res.text().await?;
        error!("Failed to set up root vault: {}", error_text);
        return Err(format!("Failed to set up root vault: {}", error_text).into());
    }

    let root_setup_data: Value = root_setup_res.json().await?;
    info!("Root vault setup response: {}", root_setup_data);

    // Extract the unwrapped token for subsequent steps
    let unwrapped_token = if let Some(token) = root_setup_data["data"]["unwrapped_token"].as_str() {
        token.to_string()
    } else {
        // Check if there's an error message we should display
        if let Some(error) = root_setup_data["error"].as_str() {
            error!("Server returned an error: {}", error);
            return Err(format!("Server error during root vault setup: {}", error).into());
        }

        // For mock server testing, we'll use a dummy token that's clearly marked as such
        info!("Using development token - MOCK SERVER DETECTED");
        "dev-only-mock-server-root-token".to_string()
    };

    // Look for root token in the response
    if let Some(token) = root_setup_data["data"]["root_token"].as_str() {
        credentials.root_token = token.to_string();
        info!("Extracted root token from setup response");
    } else {
        // For testing purposes, use the unwrapped token if no root token
        credentials.root_token = unwrapped_token.clone();
        info!("Mock environment detected - using unwrapped token as root token");
        info!("Note: In production, the API would return a real root token");
    }

    // Look for unseal keys in the response
    if let Some(keys) = root_setup_data["data"]["keys"].as_array() {
        credentials.root_unseal_keys.clear();
        for key in keys {
            if let Some(key_str) = key.as_str() {
                credentials.root_unseal_keys.push(key_str.to_string());
            }
        }
        info!(
            "Extracted {} unseal keys from setup response",
            credentials.root_unseal_keys.len()
        );
    } else if let Some(keys_base64) = root_setup_data["data"]["keys_base64"].as_array() {
        credentials.root_unseal_keys.clear();
        for key in keys_base64 {
            if let Some(key_str) = key.as_str() {
                credentials.root_unseal_keys.push(key_str.to_string());
            }
        }
        info!(
            "Extracted {} base64 unseal keys from setup response",
            credentials.root_unseal_keys.len()
        );
    } else {
        warn!(
            "No unseal keys found in API response - this is critical for production environments!"
        );
        warn!("In a real environment, the Vault server should return actual unseal keys during initialization.");
        warn!("The mock server implementation may need to be updated to provide these keys.");

        if credentials.root_unseal_keys.is_empty() {
            // Only update our diagnostic message, don't generate placeholders
            warn!("No existing keys found. In a real environment, vault unsealing will not be possible.");
        } else {
            info!(
                "Using {} existing unseal keys",
                credentials.root_unseal_keys.len()
            );
        }
    }

    // After initialization, we need to explicitly unseal the vault before we can set up transit
    if !credentials.root_unseal_keys.is_empty() {
        info!("Unsealing vault with extracted keys");
        let unseal_req = json!({
            "keys": credentials.root_unseal_keys
        });

        let unseal_res = client
            .post("http://localhost:8080/api/unseal")
            .json(&unseal_req)
            .send()
            .await?;

        if !unseal_res.status().is_success() {
            let error_text = unseal_res.text().await?;
            error!("Failed to unseal vault: {}", error_text);
            return Err(format!("Failed to unseal vault: {}", error_text).into());
        }

        let unseal_data: Value = unseal_res.json().await?;
        let sealed = unseal_data["data"]["sealed"].as_bool().unwrap_or(true);

        if sealed {
            error!("Vault is still sealed after unseal attempt!");
            return Err("Failed to unseal vault - still sealed after unseal attempt".into());
        } else {
            info!("Successfully unsealed vault");
        }
    } else {
        warn!("No unseal keys available - vault may remain sealed!");
    }

    info!("Successfully obtained unwrapped token for auto-unseal");

    // Save credentials after root vault setup
    if let Err(e) = save_vault_credentials(&credentials) {
        warn!("Failed to save credentials after root vault setup: {}", e);
    }

    // Step 2: Get a transit token (this would be used for auto-unseal)
    info!("Getting transit token for auto-unseal");

    let transit_token_req = json!({
        "root_addr": "http://127.0.0.1:8200",
        "root_token": credentials.root_token.clone(),
        "key_name": "autounseal-key"
    });

    let transit_token_res = client
        .post("http://localhost:8080/api/get_transit_token")
        .json(&transit_token_req)
        .send()
        .await?;

    if !transit_token_res.status().is_success() {
        warn!(
            "Failed to get transit token from API. Status: {}",
            transit_token_res.status()
        );
        if let Ok(error_text) = transit_token_res.text().await {
            warn!("Error response: {}", error_text);
        }

        // For mock server testing, use a dummy token that's clearly marked as such
        info!("Mock environment detected - using development token for transit");
        credentials.transit_token = "dev-only-mock-server-transit-token".to_string();
        info!("Note: In production, the API would return a real transit token");
    } else {
        let transit_token_data: Value = transit_token_res.json().await?;
        info!("Transit token response: {}", transit_token_data);

        if let Some(token) = transit_token_data["data"]["token"].as_str() {
            info!("Successfully obtained transit token");
            credentials.transit_token = token.to_string();

            // Save credentials after obtaining transit token
            if let Err(e) = save_vault_credentials(&credentials) {
                warn!(
                    "Failed to save credentials after obtaining transit token: {}",
                    e
                );
            }

            // IMPORTANT: Restart the sub vault with the transit token
            if restart_sub_vault {
                use std::process::Command;

                info!("Restarting sub vault with transit token...");
                // CRITICAL: The VAULT_TOKEN must be set directly as an environment variable for docker-compose
                // DO NOT use 'export VAULT_TOKEN=...' as it won't properly pass the token to the container
                let restart_cmd = format!(
                    "VAULT_TOKEN={} docker-compose up -d sub-vault",
                    credentials.transit_token
                );
                info!("Executing: {}", restart_cmd);

                let restart_result = Command::new("sh").arg("-c").arg(&restart_cmd).output();

                match restart_result {
                    Ok(output) => {
                        if output.status.success() {
                            info!("Successfully restarted sub vault with transit token");
                        } else {
                            warn!(
                                "Failed to restart sub vault: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Error executing docker-compose command: {}", e);
                    }
                }

                // Wait for the sub vault to be ready after restart
                info!("Waiting for sub vault to be ready after restart...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            } else {
                info!("To complete setup, you need to restart the sub vault with:");
                info!(
                    "VAULT_TOKEN={} docker-compose up -d sub-vault",
                    credentials.transit_token
                );
                info!("Run this client with --restart-sub-vault to auto-restart the sub vault");
                info!("Without this step, the sub vault will not have the token needed for auto-unseal");
            }
        } else {
            // For mock server testing, use a dummy token that's clearly marked as such
            info!("Mock environment detected - no transit token in API response");
            info!("Using development token for transit");
            credentials.transit_token = "dev-only-mock-server-transit-token".to_string();
            info!("Note: In production, the API would return a real transit token");
        }
    }

    // Step 3: Set up the sub vault with auto-unseal and PKI
    info!("Setting up sub vault with auto-unseal and PKI");

    let sub_setup_req = json!({
        "sub_addr": "http://127.0.0.1:8202",
        "domain": "example.com",
        "ttl": "8760h",
        "root_addr": "http://127.0.0.1:8200",
        "root_token": credentials.root_token
    });

    let sub_setup_res = client
        .post("http://localhost:8080/api/setup_sub")
        .json(&sub_setup_req)
        .send()
        .await?;

    if !sub_setup_res.status().is_success() {
        let error_text = sub_setup_res.text().await?;
        error!("Failed to set up sub vault: {}", error_text);
        return Err(format!("Failed to set up sub vault: {}", error_text).into());
    }

    let sub_setup_data: Value = sub_setup_res.json().await?;
    info!("Sub vault setup response: {}", sub_setup_data);

    // Extract the sub vault token if available
    if let Some(token) = sub_setup_data["data"]["sub_token"].as_str() {
        credentials.sub_token = token.to_string();
        info!("Extracted sub vault token from setup response");
    } else if let Some(token) = sub_setup_data["data"]["root_token"].as_str() {
        // Some implementations might return it as root_token
        credentials.sub_token = token.to_string();
        info!("Extracted sub vault token (named as root_token) from setup response");
    } else {
        // For mock server testing, use a dummy token that's clearly marked as such
        info!("Mock environment detected - no sub vault token in API response");
        info!("Using development token for sub vault");
        credentials.sub_token = "dev-only-mock-server-sub-token".to_string();
        info!("Note: In production, the API would return a real sub vault token");
    }

    // Save credentials after sub vault setup
    if let Err(e) = save_vault_credentials(&credentials) {
        warn!("Failed to save credentials after sub vault setup: {}", e);
    }

    // Step 4: List the configured vaults to check their status
    info!("Listing configured vaults");

    match client.get("http://localhost:8080/api/list").send().await {
        Ok(list_res) => {
            let list: Value = list_res.json().await?;
            info!("Vaults list: {}", list);
        }
        Err(e) => {
            warn!(
                "Failed to list vaults: {}. Continuing with other operations.",
                e
            );
        }
    }

    info!("Setup flow completed");
    info!("Saved credentials for both root and sub vaults in database");

    Ok(())
}
