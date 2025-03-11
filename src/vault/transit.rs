//! Transit secrets engine operations for Vault.
//!
//! This module provides functions for managing the transit secrets engine,
//! which is used for encryption/decryption operations and is a key component
//! for auto-unseal functionality.

use crate::vault::{VaultClient, VaultError};
use serde_json::json;

/// Sets up the transit secrets engine at the default path.
///
/// # Arguments
///
/// * `vault_addr` - The address of the Vault server
/// * `token` - The authentication token to use
///
/// # Returns
///
/// A Result indicating success or failure
pub async fn setup_transit_engine(vault_addr: &str, token: &str) -> Result<(), VaultError> {
    let client = VaultClient::new(vault_addr, token)?;

    // Enable the transit secrets engine
    client
        .post_with_body(
            "/v1/sys/mounts/transit",
            json!({
                "type": "transit"
            }),
        )
        .await?;

    Ok(())
}

/// Creates a new encryption key in the transit engine.
///
/// # Arguments
///
/// * `vault_addr` - The address of the Vault server
/// * `token` - The authentication token to use
/// * `key_name` - The name of the key to create
///
/// # Returns
///
/// A Result indicating success or failure
pub async fn create_transit_key(
    vault_addr: &str,
    token: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    let client = VaultClient::new(vault_addr, token)?;

    // Create a new encryption key
    client
        .put_with_body(
            &format!("/v1/transit/keys/{}", key_name),
            json!({
                "derived": false,
                "exportable": false
            }),
        )
        .await?;

    Ok(())
}

/// Creates a policy for auto-unseal operations using the transit engine.
///
/// # Arguments
///
/// * `vault_addr` - The address of the Vault server
/// * `token` - The authentication token to use
/// * `policy_name` - The name of the policy to create
/// * `key_name` - The name of the encryption key to use
///
/// # Returns
///
/// A Result indicating success or failure
pub async fn create_transit_unseal_policy(
    vault_addr: &str,
    token: &str,
    policy_name: &str,
    key_name: &str,
) -> Result<(), VaultError> {
    let client = VaultClient::new(vault_addr, token)?;

    let policy_hcl = format!(
        r#"
        # Allow decryption using transit engine for auto-unseal
        path "transit/decrypt/{}" {{
            capabilities = ["update"]
        }}

        # Allow encryption using transit engine for auto-unseal
        path "transit/encrypt/{}" {{
            capabilities = ["update"]
        }}
        "#,
        key_name, key_name
    );

    // Create the policy
    client
        .put_with_body(
            &format!("/v1/sys/policies/acl/{}", policy_name),
            json!({
                "policy": policy_hcl
            }),
        )
        .await?;

    Ok(())
}

/// Generates a token with transit unseal policy attached.
///
/// # Arguments
///
/// * `vault_addr` - The address of the Vault server
/// * `token` - The authentication token to use
/// * `policy_name` - The name of the policy to attach to the token
///
/// # Returns
///
/// A Result containing the generated token or an error
pub async fn generate_transit_unseal_token(
    vault_addr: &str,
    token: &str,
    policy_name: &str,
) -> Result<String, VaultError> {
    let client = VaultClient::new(vault_addr, token)?;

    let response = client
        .post_with_body(
            "/v1/auth/token/create",
            json!({
                "policies": [policy_name],
                "ttl": "768h",  // Default 32 days TTL
                "display_name": "transit-unseal-token",
                "renewable": true
            }),
        )
        .await?;

    // Extract token from response
    match response
        .get("auth")
        .and_then(|auth| auth.get("client_token"))
    {
        Some(client_token) => client_token
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::ParseError("Failed to parse client token".to_string())),
        None => Err(VaultError::ParseError(
            "Client token not found in response".to_string(),
        )),
    }
}

/// Generates a wrapped token with transit unseal policy attached.
///
/// # Arguments
///
/// * `vault_addr` - The address of the Vault server
/// * `token` - The authentication token to use
/// * `policy_name` - The name of the policy to attach to the token
/// * `wrap_ttl` - The TTL for the response-wrapped token (e.g., "60s", "30m", "1h")
///
/// # Returns
///
/// A Result containing the wrapped token information or an error
pub async fn generate_wrapped_transit_token(
    vault_addr: &str,
    token: &str,
    policy_name: &str,
    wrap_ttl: &str,
) -> Result<String, VaultError> {
    let mut client = VaultClient::new(vault_addr, token)?;

    // Add wrapping header
    client.add_header("X-Vault-Wrap-TTL", wrap_ttl);

    let response = client
        .post_with_body(
            "/v1/auth/token/create",
            json!({
                "policies": [policy_name],
                "ttl": "768h",
                "display_name": "transit-unseal-token",
                "renewable": true
            }),
        )
        .await?;

    // Extract wrapped token from response
    match response.get("wrap_info").and_then(|wrap| wrap.get("token")) {
        Some(wrapped_token) => wrapped_token
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::ParseError("Failed to parse wrapped token".to_string())),
        None => Err(VaultError::ParseError(
            "Wrapped token not found in response".to_string(),
        )),
    }
}
