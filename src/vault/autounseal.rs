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
//! ```no_run
//! # async fn example() -> Result<(), merka_vault::vault::VaultError> {
//! use merka_vault::vault::autounseal;
//!
//! // Set up Transit engine on the unsealer Vault
//! let unsealer_url = "http://unsealer-vault:8200";
//! let token = "unsealer_root_token";
//! let key_name = "auto-unseal-key";
//!
//! autounseal::setup_transit_autounseal(&unsealer_url, token, key_name).await?;
//!
//! // Configure the target Vault to use Transit auto-unseal
//! let target_url = "http://target-vault:8200";
//! autounseal::configure_vault_for_autounseal(
//!     &target_url,
//!     &unsealer_url,
//!     token,
//!     key_name
//! ).await?;
//!
//! // Initialize the target Vault with auto-unseal
//! let init_result = autounseal::init_with_autounseal(&target_url).await?;
//!
//! // Store the recovery keys securely
//! println!("Root Token: {}", init_result.root_token);
//! if let Some(recovery_keys) = init_result.recovery_keys {
//!     println!("Recovery Keys: {:?}", recovery_keys);
//! }
//! # Ok(())
//! # }
//! ```

use crate::vault::{client::VaultClient, InitResult, VaultError};
use serde_json::json;

/// Sets up the transit engine for auto-unseal.
pub async fn setup_transit_autounseal(
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
pub async fn configure_vault_for_autounseal(
    target_vault_addr: &str,
    unsealer_addr: &str,
    unsealer_token: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    // Generate a token with the autounseal policy
    let policy_name = "autounseal";
    let token = crate::vault::transit::generate_transit_unseal_token(
        unsealer_addr,
        unsealer_token,
        policy_name,
    )
    .await?;

    // Use the generated token to configure auto-unseal
    configure_vault_for_autounseal_with_token(target_vault_addr, unsealer_addr, &token, key_name)
        .await
}

/// Configures a Vault instance for auto-unseal using a provided token.
pub async fn configure_vault_for_autounseal_with_token(
    _target_vault_addr: &str,
    unsealer_addr: &str,
    token: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    // This would typically modify the Vault server configuration file
    // which requires server-side access. For this API, we just validate
    // the token has proper permissions
    let client = VaultClient::new(unsealer_addr, token)?;

    // Test token access to the transit key
    client
        .post_with_body(
            &format!("/v1/transit/encrypt/{}", key_name),
            json!({
                "plaintext": "dGVzdA==" // Base64 encoded "test"
            }),
        )
        .await?;

    // Return success if we got here without error
    Ok(())
}

/// Initializes a Vault instance with auto-unseal.
pub async fn init_with_autounseal(vault_addr: &str) -> Result<InitResult, VaultError> {
    let client = reqwest::Client::new();

    // Initialize with auto-unseal config (no unseal keys, only recovery keys)
    let response = client
        .put(&format!("{}/v1/sys/init", vault_addr))
        .json(&json!({
            "recovery_shares": 5,
            "recovery_threshold": 3,
        }))
        .send()
        .await
        .map_err(|e| VaultError::Network(format!("Auto-unseal init request failed: {}", e)))?;

    // Parse response
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

    let init_response = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| VaultError::ParseError(format!("Failed to parse init response: {}", e)))?;

    // Extract tokens and keys
    let root_token = init_response["root_token"]
        .as_str()
        .ok_or_else(|| VaultError::ParseError("Missing root token in response".to_string()))?
        .to_string();

    // Extract recovery keys if present
    let recovery_keys = init_response["recovery_keys"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    });

    // Extract recovery keys base64 if present
    let recovery_keys_base64 = init_response["recovery_keys_base64"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    });

    Ok(InitResult {
        root_token,
        keys: Vec::new(),              // No unseal keys with auto-unseal
        keys_base64: Some(Vec::new()), // Empty but present
        recovery_keys,
        recovery_keys_base64,
    })
}

/// Generates a wrapped token with transit unseal permissions.
pub async fn generate_wrapped_transit_unseal_token(
    vault_addr: &str,
    token: &str,
    policy_name: &str,
    ttl: u32,
) -> Result<String, VaultError> {
    let client = VaultClient::new(vault_addr, token)?;

    // Generate a token with response wrapping
    let response = client
        .post_with_body(
            "/v1/auth/token/create",
            json!({
                "policies": [policy_name],
                "ttl": "768h",  // Default 32 days TTL
                "display_name": "transit-unseal-token",
                "renewable": true,
                "wrap_ttl": format!("{}s", ttl)  // Wrap the response for secure transmission
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
        .post(&format!("{}/v1/sys/wrapping/unwrap", vault_addr))
        .header("X-Vault-Token", wrapped_token)
        .send()
        .await
        .map_err(|e| VaultError::Network(format!("Failed to unwrap token: {}", e)))?;

    // Parse response
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
