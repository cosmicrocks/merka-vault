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

    // If the vault is already initialized, we need to provide a token or proceed to get a transit token
    if initialized {
        info!("Vault is already initialized. Attempting to retrieve token from database.");

        // Try to load existing credentials from the database
        match load_vault_credentials() {
            Ok(loaded_creds) => {
                info!("Successfully loaded credentials from database.");

                if !loaded_creds.root_token.is_empty() {
                    info!("Found valid root token in database.");
                    credentials.root_token = loaded_creds.root_token;

                    // Also load other credentials
                    credentials.root_unseal_keys = loaded_creds.root_unseal_keys;
                    credentials.transit_token = loaded_creds.transit_token;
                    credentials.sub_token = loaded_creds.sub_token;
                } else {
                    error!("Root token in database is empty. Cannot proceed with an initialized vault without a token.");
                    error!("Please provide a valid root token when running this tool.");
                    error!("You can use environment variables: VAULT_TOKEN=your_token cargo run --example test_client");
                    return Err("Missing root token for initialized vault".into());
                }
            }
            Err(e) => {
                error!("Failed to load credentials from database: {}", e);
                error!("Vault is already initialized but we don't have a valid root token in the database.");
                error!("Please provide a valid root token when running this tool.");
                error!("You can use environment variables: VAULT_TOKEN=your_token cargo run --example test_client");
                return Err("Missing root token for initialized vault".into());
            }
        }
    } else {
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

            // If the error is because the vault is already initialized, continue
            if error_text.contains("already initialized") {
                info!("Vault is already initialized. Proceeding to get transit token.");

                // Check if we have a root token
                if credentials.root_token.is_empty() {
                    // Don't use a default token - inform user that we need a valid token
                    error!("Vault is already initialized but we don't have a valid root token.");
                    error!("Please provide a valid root token when running this tool.");
                    error!("You can try running with your own token: VAULT_TOKEN=your_token cargo run --example test_client");
                    return Err("Missing root token for initialized vault".into());
                }
            } else {
                error!("Failed to set up root vault: {}", error_text);
                return Err(format!("Failed to set up root vault: {}", error_text).into());
            }
        } else {
            let response_text = root_setup_res.text().await?;
            info!("Root vault setup raw response: {}", response_text);

            // Parse the response text into JSON
            let root_setup_data: Value = serde_json::from_str(&response_text)?;
            info!("Root vault setup parsed response: {}", root_setup_data);

            // Extract the unwrapped token for subsequent steps
            let unwrapped_token = if let Some(token) =
                root_setup_data["data"]["unwrapped_token"].as_str()
            {
                token.to_string()
            } else {
                // Check if there's an error message we should display
                if let Some(error) = root_setup_data["error"].as_str() {
                    error!("Server returned an error: {}", error);
                    return Err(format!("Server error during root vault setup: {}", error).into());
                }

                // Cannot continue without a valid token
                error!("No valid token found in API response");
                return Err("Failed to extract a valid token from the setup response".into());
            };

            // Extract the root token or use unwrapped token if root token is empty
            if let Some(token) = root_setup_data["data"]["root_token"].as_str() {
                if !token.is_empty() {
                    credentials.root_token = token.to_string();
                    info!(
                        "Extracted root token from setup response: {} chars",
                        credentials.root_token.len()
                    );
                } else {
                    // If root_token is empty, use unwrapped_token as fallback
                    info!("Root token is empty, using unwrapped_token as root token");
                    credentials.root_token = unwrapped_token.clone();
                    info!(
                        "Using unwrapped token as root token: {} chars",
                        credentials.root_token.len()
                    );
                }
            } else {
                // If root_token is not present, use unwrapped_token
                credentials.root_token = unwrapped_token.clone();
                info!(
                    "No root_token in response, using unwrapped token as root token: {} chars",
                    credentials.root_token.len()
                );
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
                warn!(
                    "The mock server implementation may need to be updated to provide these keys."
                );

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
        }
    }

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
        let error_text = transit_token_res.text().await.unwrap_or_default();
        warn!("Error response: {}", error_text);

        // Try alternative approach if it seems like a permission issue
        if error_text.contains("permission") || error_text.contains("Permission denied") {
            info!("Permission issue detected. Trying alternative approach to get transit token...");

            // Try the get_root_token endpoint as a fallback
            let root_token_res = client
                .post("http://localhost:8080/api/get_root_token")
                .json(&json!({
                    "unwrapped_token": credentials.root_token,
                }))
                .send()
                .await;

            if let Ok(alt_response) = root_token_res {
                if alt_response.status().is_success() {
                    if let Ok(alt_data) = alt_response.json::<Value>().await {
                        info!("Alternative token approach response: {}", alt_data);

                        if let Some(token) = alt_data
                            .get("data")
                            .and_then(|d| d.get("root_token"))
                            .and_then(|t| t.as_str())
                        {
                            credentials.transit_token = token.to_string();
                            info!(
                                "Got alternative token: {} chars",
                                credentials.transit_token.len()
                            );
                        } else {
                            error!("Could not extract transit token from alternative approach.");
                            error!("Cannot proceed without a valid transit token.");
                            return Err("Failed to obtain transit token".into());
                        }
                    }
                } else {
                    error!("Alternative approach also failed.");
                    return Err(
                        "Failed to obtain transit token through alternative approach".into(),
                    );
                }
            } else {
                error!("Failed to make request for alternative token approach.");
                return Err("Failed to obtain transit token".into());
            }
        } else {
            error!("Failed to get transit token and no alternatives available.");
            error!("Cannot proceed without a valid transit token.");
            return Err("Failed to obtain transit token".into());
        }
    } else {
        let response_text = transit_token_res.text().await?;
        info!("Transit token raw response: {}", response_text);

        // Parse the response text into JSON
        match serde_json::from_str::<Value>(&response_text) {
            Ok(transit_token_data) => {
                info!("Transit token parsed response: {}", transit_token_data);

                // Check for token in different possible locations in the response
                let mut found_token = false;

                // Try data.token path
                if let Some(token) = transit_token_data
                    .get("data")
                    .and_then(|d| d.get("token"))
                    .and_then(|t| t.as_str())
                {
                    credentials.transit_token = token.to_string();
                    found_token = true;
                    info!(
                        "Extracted transit token from data.token: {} chars",
                        credentials.transit_token.len()
                    );
                }
                // Try data.unwrapped_token path
                else if let Some(token) = transit_token_data
                    .get("data")
                    .and_then(|d| d.get("unwrapped_token"))
                    .and_then(|t| t.as_str())
                {
                    credentials.transit_token = token.to_string();
                    found_token = true;
                    info!(
                        "Extracted transit token from data.unwrapped_token: {} chars",
                        credentials.transit_token.len()
                    );
                }
                // Try other potential locations
                else if let Some(token) = transit_token_data.get("token").and_then(|t| t.as_str())
                {
                    credentials.transit_token = token.to_string();
                    found_token = true;
                    info!(
                        "Extracted transit token from root.token: {} chars",
                        credentials.transit_token.len()
                    );
                }

                if !found_token {
                    // For mock server testing, use a dummy token that's clearly marked as such
                    info!("Mock environment detected - no transit token in API response");
                    error!("Cannot proceed without a valid transit token");
                    error!("Please check your vault configuration and ensure you have proper permissions");
                    return Err("No valid transit token available".into());
                }
            }
            Err(e) => {
                warn!("Failed to parse transit token response as JSON: {}", e);

                // For mock server testing, use a dummy token that's clearly marked as such
                info!("Mock environment detected - invalid JSON response");
                info!("Using development token for transit");
                credentials.transit_token = "dev-only-mock-server-transit-token".to_string();
                info!("Note: In production, the API would return a real transit token");
            }
        }
    }

    // Save credentials after obtaining transit token
    if let Err(e) = save_vault_credentials(&credentials) {
        warn!(
            "Failed to save credentials after obtaining transit token: {}",
            e
        );
    }

    // IMPORTANT: Restart the sub vault with the transit token
    if restart_sub_vault && !credentials.transit_token.is_empty() {
        use std::process::Command;

        info!(
            "Restarting sub vault with transit token (length: {})...",
            credentials.transit_token.len()
        );
        info!(
            "Transit token starts with: {}",
            if credentials.transit_token.len() > 10 {
                format!("{}...", &credentials.transit_token[..10])
            } else {
                credentials.transit_token.clone()
            }
        );

        // CRITICAL: The VAULT_TOKEN must be set directly as an environment variable for docker-compose
        // DO NOT use 'export VAULT_TOKEN=...' as it won't properly pass the token to the container
        let restart_cmd = format!(
            "VAULT_TOKEN=\"{}\" docker-compose up -d sub-vault",
            credentials.transit_token
        );
        info!("Executing: {}", restart_cmd);

        let restart_result = Command::new("sh").arg("-c").arg(&restart_cmd).output();

        match restart_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully restarted sub vault with transit token");
                    info!(
                        "Command stdout: {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
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
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    } else if !restart_sub_vault {
        info!("To complete setup, you need to restart the sub vault with:");
        info!(
            "VAULT_TOKEN=\"{}\" docker-compose up -d sub-vault",
            credentials.transit_token
        );
        info!("Run this client with --restart-sub-vault to auto-restart the sub vault");
        info!("Without this step, the sub vault will not have the token needed for auto-unseal");
    } else if credentials.transit_token.is_empty() {
        warn!("Cannot restart sub vault because transit token is empty");
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
        error!("No sub vault token found in API response");
        error!("Cannot complete the setup without a valid sub vault token");
        return Err("Failed to extract sub vault token from response".into());
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
