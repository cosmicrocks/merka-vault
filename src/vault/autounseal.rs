//! Vault Auto-Unseal functionality using Transit secrets engine
//!
//! This module implements the automatic unsealing of Vault servers using the
//! Transit secrets engine from another Vault server. Auto-unseal eliminates
//! the need for manual operator intervention during Vault restarts.
//!
//! # Auto-Unseal Flow
//!
//! The auto-unseal process follows these steps:
//!
//! 1. **Setup**: Configure a Vault server with Transit engine and create an encryption key
//! 2. **Configuration**: Configure the target Vault to use Transit auto-unseal
//! 3. **Initialization**: Initialize the target Vault with recovery keys instead of unseal keys
//! 4. **Automatic Unsealing**: When the target Vault starts, it uses the Transit engine to decrypt its master key
//!
//! # Example
//!
//! This example is for internal use only and not part of the public API.
//! ```ignore
//! // This is an internal API not meant to be used directly
//! // See the actor API or CLI for how to set up auto-unseal
//!
//! // Example of what the setup would look like internally:
//! // Set up Transit engine on the unsealer Vault
//! let unsealer_url = "http://unsealer-vault:8200";
//! let token = "unsealer_root_token";
//! let key_name = "auto-unseal-key";
//!
//! // Set up transit, configure target vault, and initialize it
//! ```

use serde_json::json;
use tracing::{error, warn};

#[cfg(any(test, feature = "full-api"))]
use crate::vault::{init::InitResult, VaultClient, VaultError};
#[cfg(not(any(test, feature = "full-api")))]
use crate::vault::{init::InitResult, VaultError};

use tokio;

/// Sets up the transit engine for auto-unseal.
pub async fn setup_transit_autounseal(
    vault_addr: &str,
    token: &str,
    key_name: &str,
) -> Result<bool, VaultError> {
    // Add retry logic for race conditions during testing
    let max_retries = 5;
    let mut last_error = None;

    for attempt in 1..=max_retries {
        tracing::info!(
            "Setting up transit engine, attempt {}/{}",
            attempt,
            max_retries
        );

        match setup_transit_engine_internal(vault_addr, token, key_name).await {
            Ok(_) => {
                tracing::info!(
                    "Successfully set up transit engine after {} attempts",
                    attempt
                );
                return Ok(true);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to set up transit engine (attempt {}/{}): {}",
                    attempt,
                    max_retries,
                    e
                );
                last_error = Some(e);

                // Don't sleep on the last attempt
                if attempt < max_retries {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| VaultError::Api("Max retries exceeded".to_string())))
}

// Internal function that does the actual setup work
async fn setup_transit_engine_internal(
    vault_addr: &str,
    token: &str,
    key_name: &str,
) -> Result<bool, VaultError> {
    // Enable transit engine
    crate::vault::transit::setup_transit_engine(vault_addr, token).await?;

    // Create encryption key for auto-unseal
    crate::vault::transit::create_transit_key(vault_addr, token, key_name).await?;

    // Create a policy for the auto-unseal token
    let policy_name = "autounseal";
    crate::vault::transit::create_transit_unseal_policy(vault_addr, token, policy_name, key_name)
        .await?;

    Ok(true)
}

/// Configures a Vault instance to use transit auto-unseal.
#[cfg(any(test, feature = "full-api"))]
pub async fn configure_vault_for_autounseal(
    target_addr: &str,
    unsealer_addr: &str,
    unsealer_token: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    tracing::info!(
        "Configuring Vault at {} for auto-unseal using unsealer at {}",
        target_addr,
        unsealer_addr
    );

    // Check if target vault is already initialized
    match super::status::get_vault_status(target_addr).await {
        Ok(status) => {
            if status.initialized {
                tracing::info!(
                    "Target Vault is already initialized, skipping auto-unseal configuration"
                );
                return Ok(());
            }
            tracing::info!(
                "Target Vault not initialized, proceeding with auto-unseal configuration"
            );
        }
        Err(e) => warn!("Could not check target Vault status: {}", e),
    }

    // Generate a token with the autounseal policy
    let policy_name = "autounseal";
    let token = crate::vault::transit::generate_transit_unseal_token(
        unsealer_addr,
        unsealer_token,
        policy_name,
    )
    .await?;

    // Use the generated token to configure auto-unseal
    configure_vault_for_autounseal_with_token(target_addr, unsealer_addr, &token, key_name).await?;

    tracing::info!("Auto-unseal configuration complete for {}", target_addr);
    Ok(())
}

/// Configures a Vault instance for auto-unseal using a provided token.
///
/// Note: This function only validates that the token has proper permissions.
/// The actual configuration must be set in the Vault server's configuration file
/// using a "seal" stanza like:
///
/// ```text
/// seal "transit" {
///   address         = "http://unsealer-vault:8200"
///   token           = "s.token1234"  # The token validated by this function
///   key_name        = "autounseal-key"
///   mount_path      = "transit/"
///   tls_skip_verify = true
/// }
/// ```
#[cfg(any(test, feature = "full-api"))]
pub async fn configure_vault_for_autounseal_with_token(
    target_vault_addr: &str,
    unsealer_addr: &str,
    token: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    tracing::info!(
        "Validating token for auto-unseal from {} to {} using key {}",
        target_vault_addr,
        unsealer_addr,
        key_name
    );

    // Validate the token has proper permissions
    let client = VaultClient::new(unsealer_addr, token)?;

    // Test token access to the transit key by encrypting a test value
    let encrypt_result = client
        .post_with_body(
            &format!("/v1/transit/encrypt/{}", key_name),
            json!({
                "plaintext": "dGVzdA==" // Base64 encoded "test"
            }),
        )
        .await;

    match encrypt_result {
        Ok(_) => tracing::info!("✅ Token successfully validated for Transit encrypt operations"),
        Err(e) => {
            error!("❌ Token validation failed: {}", e);
            error!("If you're experiencing a token issue, make sure to:");
            error!("  1. Check that the token exists and is not expired");
            error!("  2. The policy has permissions for 'transit/encrypt/{key_name}' and 'transit/decrypt/{key_name}'");
            error!("  3. Update the VAULT_TOKEN environment variable in your sub-vault container");
            error!("  4. Check the network connectivity between the containers");

            return Err(VaultError::Api(format!(
                "Auto-unseal token does not have proper permissions: {}",
                e
            )));
        }
    }

    // This only validates the token - the actual configuration is handled
    // via the Vault configuration file with a seal stanza
    tracing::info!("✅ Token successfully validated but remember:");
    tracing::info!("  - This function only validates token permissions");
    tracing::info!("  - Your Vault configuration file must include a seal stanza:");
    tracing::info!("    seal \"transit\" {{");
    tracing::info!("      address         = \"{}\"", unsealer_addr);
    tracing::info!("      token           = \"{}\"", token);
    tracing::info!("      key_name        = \"{}\"", key_name);
    tracing::info!("      mount_path      = \"transit/\"");
    tracing::info!("      tls_skip_verify = true");
    tracing::info!("    }}");

    Ok(())
}

/// Initializes a Vault instance with auto-unseal.
pub async fn init_with_autounseal(vault_addr: &str) -> Result<InitResult, VaultError> {
    tracing::info!("Initializing vault with auto-unseal at {}", vault_addr);

    // Check if vault is already initialized
    match super::status::get_vault_status(vault_addr).await {
        Ok(status) => {
            if status.initialized {
                tracing::info!("Vault at {} is already initialized", vault_addr);
                return Err(VaultError::AlreadyInitialized);
            }
            tracing::info!("Vault not initialized, proceeding...");
        }
        Err(e) => {
            warn!("Could not check vault initialization status: {}", e);
            tracing::info!("Proceeding with initialization attempt anyway");
        }
    }

    let client = reqwest::Client::new();

    // Initialize with auto-unseal config (no unseal keys, only recovery keys)
    let response = client
        .put(format!("{}/v1/sys/init", vault_addr))
        .json(&json!({
            "recovery_shares": 5,
            "recovery_threshold": 3,
        }))
        .send()
        .await
        .map_err(|e| VaultError::Network(format!("Auto-unseal init request failed: {}", e)))?;

    // Store the status code before we consume the response
    let status_code = response.status().as_u16();

    if !response.status().is_success() {
        return Err(VaultError::HttpStatus(
            status_code,
            response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string()),
        ));
    }

    // Get a clone of the response body for later JSON parsing
    let body = response
        .text()
        .await
        .map_err(|e| VaultError::ParseError(format!("Failed to get response body: {}", e)))?;

    // Parse the body first to extract individual fields
    let init_response: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| VaultError::ParseError(format!("Failed to parse init response: {}", e)))?;

    // Extract tokens and keys
    let _root_token = init_response["root_token"]
        .as_str()
        .ok_or_else(|| VaultError::ParseError("Missing root token in response".to_string()))?
        .to_string();

    // Extract recovery keys if present (unused but kept for debug/validation)
    let _recovery_keys = init_response["recovery_keys"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    });

    // Extract recovery keys base64 if present (unused but kept for debug/validation)
    let _recovery_keys_base64 = init_response["recovery_keys_base64"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    });

    match status_code {
        200 => {
            tracing::info!("Vault initialized successfully with auto-unseal");

            // Parse the response body again into the InitResult struct
            let result: InitResult = serde_json::from_str(&body).map_err(|e| {
                error!("Failed to parse auto-unseal init response: {}", e);
                VaultError::ParseError(e.to_string())
            })?;

            Ok(result)
        }
        403 => {
            error!("Permission denied during auto-unseal initialization");
            Err(VaultError::Api("Permission denied".to_string()))
        }
        503 => {
            error!("Vault sealed error during auto-unseal initialization");
            Err(VaultError::Sealed("Vault is sealed".to_string()))
        }
        status => {
            error!(
                "Unexpected error during auto-unseal initialization. Status: {}",
                status
            );
            Err(VaultError::Api(format!("HTTP status {}", status)))
        }
    }
}

/// Generates a wrapped token with transit unseal permissions.
#[cfg(any(test, feature = "full-api"))]
pub async fn generate_wrapped_transit_unseal_token(
    vault_addr: &str,
    token: &str,
    policy_name: &str,
    _ttl: u32,
) -> Result<String, VaultError> {
    let client = VaultClient::new(vault_addr, token)?;

    // Generate a token with response wrapping
    let response = client
        .post_with_body(
            "/v1/auth/token/create",
            json!({
                "policies": [policy_name],
                "period": "768h",
                "display_name": "transit-unseal-token",
                "renewable": true
            }),
        )
        .await?;

    // Extract wrapped token from response
    match response.get("wrap_info").and_then(|w| w.get("token")) {
        Some(wrapped_token) => wrapped_token
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::ParseError("Failed to parse wrapped token".to_string())),
        None => Err(VaultError::ParseError(
            "Wrapped token not found in response".to_string(),
        )),
    }
}

/// Unwraps a token that was wrapped using Vault's response wrapping.
pub async fn unwrap_token(vault_addr: &str, wrapped_token: &str) -> Result<String, VaultError> {
    let client = reqwest::Client::new();

    // Unwrap the token - this doesn't require authentication as the wrap token itself is the auth
    let response = client
        .post(format!("{}/v1/sys/wrapping/unwrap", vault_addr))
        .header("X-Vault-Token", wrapped_token)
        .send()
        .await
        .map_err(|e| VaultError::Network(format!("Failed to unwrap token: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(VaultError::HttpStatus(
            status.as_u16(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string()),
        ));
    }

    let unwrap_response = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| VaultError::ParseError(format!("Failed to parse unwrap response: {}", e)))?;

    // Extract the token from the unwrapped response
    match unwrap_response
        .get("auth")
        .and_then(|a| a.get("client_token"))
    {
        Some(client_token) => client_token.as_str().map(|s| s.to_string()).ok_or_else(|| {
            VaultError::ParseError("Failed to parse unwrapped client token".to_string())
        }),
        None => Err(VaultError::ParseError(
            "Client token not found in unwrap response".to_string(),
        )),
    }
}

/// Generates a new transit unseal token and displays how to configure it.
/// This is a convenience function for regenerating tokens when the old one expires or has issues.
///
/// # Arguments
///
/// * `vault_addr` - Address of the unsealer Vault
/// * `admin_token` - Admin token with permission to create new tokens
/// * `key_name` - Name of the transit key used for auto-unsealing
///
/// # Returns
///
/// A `Result` containing the new token or an error
#[cfg(any(test, feature = "full-api"))]
pub async fn regenerate_transit_unseal_token(
    vault_addr: &str,
    admin_token: &str,
    key_name: &str,
) -> Result<String, VaultError> {
    // First ensure the policy exists
    let policy_name = "autounseal";
    match crate::vault::transit::create_transit_unseal_policy(
        vault_addr,
        admin_token,
        policy_name,
        key_name,
    )
    .await
    {
        Ok(_) => tracing::info!("✅ Transit unseal policy created or updated"),
        Err(e) => {
            error!("❌ Failed to create transit unseal policy: {}", e);
            return Err(e);
        }
    }

    // Generate a new token with the policy
    let new_token = match crate::vault::transit::generate_transit_unseal_token(
        vault_addr,
        admin_token,
        policy_name,
    )
    .await
    {
        Ok(token) => {
            tracing::info!("✅ Successfully generated new transit unseal token");
            token
        }
        Err(e) => {
            error!("❌ Failed to generate transit unseal token: {}", e);
            return Err(e);
        }
    };

    // Test the new token
    match configure_vault_for_autounseal_with_token("localhost", vault_addr, &new_token, key_name)
        .await
    {
        Ok(_) => tracing::info!("✅ New token successfully validated"),
        Err(e) => {
            error!("❌ Validation of new token failed: {}", e);
            error!("The token was generated but may not have proper permissions");
        }
    }

    // Print instructions for updating the token
    tracing::info!("To update your auto-unseal configuration:");
    tracing::info!("1. Set the VAULT_TOKEN environment variable for your target Vault:");
    tracing::info!("   export VAULT_TOKEN=\"{}\"", new_token);
    tracing::info!("   or update your docker-compose.yml environment section");
    tracing::info!("2. Restart your target Vault server");

    Ok(new_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;

    // Unit test for unwrap_token functionality
    #[tokio::test]
    async fn test_token_wrapping_unwrapping() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();

        // This test would verify that token wrapping and unwrapping works
        // To keep it as a proper unit test, we would need to mock the vault APIs
        // For now, this is just a placeholder to show where a proper unit test would go

        Ok(())
    }
}
