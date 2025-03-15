//! Transit secrets engine operations for Vault.
//!
//! This module provides functions for managing the transit secrets engine,
//! which is used for encryption/decryption operations and is a key component
//! for auto-unseal functionality.

use crate::vault::{VaultClient, VaultError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Response structure for token creation
#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    request_id: String,
    lease_id: String,
    renewable: bool,
    lease_duration: u64,
    auth: TokenAuth,
}

/// Auth section of token response
#[derive(Debug, Serialize, Deserialize)]
struct TokenAuth {
    client_token: String,
    accessor: String,
    policies: Vec<String>,
    token_policies: Vec<String>,
    metadata: Option<serde_json::Map<String, Value>>,
    renewable: bool,
    lease_duration: u64,
}

/// Wrapped token response structure
#[derive(Debug, Serialize, Deserialize)]
struct WrappedResponse {
    request_id: String,
    wrap_info: WrapInfo,
}

/// Wrap info section
#[derive(Debug, Serialize, Deserialize)]
struct WrapInfo {
    token: String,
    ttl: u64,
    creation_time: String,
    creation_path: String,
}

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
    let _response = client
        .post_with_body(
            "/v1/sys/mounts/transit",
            json!({
                "type": "transit"
            }),
        )
        .await?;

    // Response is already checked for errors by VaultClient
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
    let _response = client
        .put_with_body(
            &format!("/v1/transit/keys/{}", key_name),
            json!({
                "derived": false,
                "exportable": false
            }),
        )
        .await?;

    // Response is already checked for errors by VaultClient
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

        # Allow token renewal for auto-unseal
        path "auth/token/renew-self" {{
            capabilities = ["update"]
        }}
        "#,
        key_name, key_name
    );

    // Create the policy
    let _response = client
        .put_with_body(
            &format!("/v1/sys/policies/acl/{}", policy_name),
            json!({
                "policy": policy_hcl
            }),
        )
        .await?;

    // Response is already checked for errors by VaultClient
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

    // Extract client token directly from the response value
    let client_token = response
        .get("auth")
        .and_then(|auth| auth.get("client_token"))
        .and_then(|token| token.as_str())
        .ok_or_else(|| VaultError::Api("Failed to extract client token".to_string()))?;

    Ok(client_token.to_string())
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
            "/v1/auth/token/create-orphan",
            json!({
                "policies": [policy_name],
                "period": "24h",
                "display_name": "transit-unseal-token",
                "renewable": true
            }),
        )
        .await?;

    // Extract the wrapped token directly from the response value
    let wrapped_token = response
        .get("wrap_info")
        .and_then(|wrap| wrap.get("token"))
        .and_then(|token| token.as_str())
        .ok_or_else(|| VaultError::Api("Failed to extract wrapped token".to_string()))?;

    Ok(wrapped_token.to_string())
}
