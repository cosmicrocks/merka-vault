//! Transit secrets engine operations for Vault.
//!
//! This module provides functions for managing the transit secrets engine,
//! which is used for encryption/decryption operations and is a key component
//! for auto-unseal functionality.

use crate::vault::{VaultClient, VaultError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

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

    // Try to enable the transit secrets engine
    let response = client
        .post_with_body(
            "/v1/sys/mounts/transit",
            json!({
                "type": "transit"
            }),
        )
        .await;

    // Handle specific error cases - it's OK if transit is already enabled
    match response {
        Ok(_) => Ok(()),
        Err(VaultError::HttpStatus(_status, error_text))
            if error_text.contains("path is already in use") =>
        {
            info!("Transit engine already enabled, continuing");
            Ok(())
        }
        Err(e) => {
            warn!("Failed to enable transit engine: {}", e);
            Err(e)
        }
    }
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

    // Try to create a new encryption key
    let response = client
        .put_with_body(
            &format!("/v1/transit/keys/{}", key_name),
            json!({
                "derived": false,
                "exportable": false
            }),
        )
        .await;

    // Handle specific error cases - it's OK if key already exists
    match response {
        Ok(_) => Ok(()),
        Err(VaultError::HttpStatus(_status, error_text))
            if error_text.contains("already exists") =>
        {
            info!("Transit key '{}' already exists, continuing", key_name);
            Ok(())
        }
        Err(e) => {
            warn!("Failed to create transit key '{}': {}", key_name, e);
            Err(e)
        }
    }
}

/// Creates a policy for transit-based auto-unseal.
///
/// # Arguments
///
/// * `vault_addr` - The address of the Vault server
/// * `token` - The authentication token to use
/// * `policy_name` - The name of the policy to create
/// * `key_name` - The name of the transit key to use
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

    // Create minimal policy for transit key usage
    let policy_hcl = format!(
        r#"
        # Allow token creation
        path "auth/token/create" {{
            capabilities = ["update"]
        }}

        # Allow encryption operations with the key
        path "transit/encrypt/{}" {{
            capabilities = ["update"]
        }}

        # Allow decryption operations with the key
        path "transit/decrypt/{}" {{
            capabilities = ["update"]
        }}
        "#,
        key_name, key_name
    );

    // Attempt to put the policy
    let response = client
        .put_with_body(
            &format!("/v1/sys/policies/acl/{}", policy_name),
            json!({
                "policy": policy_hcl,
            }),
        )
        .await;

    // Handle specific error cases - for policies we generally want to overwrite
    // but we'll log if there were issues
    match response {
        Ok(_) => {
            info!("Created/updated auto-unseal policy: {}", policy_name);
            Ok(())
        }
        Err(e) => {
            warn!("Failed to create/update policy '{}': {}", policy_name, e);
            Err(e)
        }
    }
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
#[cfg(any(test, feature = "full-api"))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;

    use crate::vault::status::get_vault_status;
    use crate::vault::test_utils::{setup_vault_container, wait_for_vault_ready, VaultMode};

    use tracing::info;

    // Test for transit engine setup error handling with invalid token
    #[tokio::test]
    async fn test_transit_invalid_token() -> Result<(), Box<dyn std::error::Error>> {
        // Any invalid address/token combination will cause an error
        let invalid_token = "invalid-token";
        let result = setup_transit_engine("http://127.0.0.1:8200", invalid_token).await;

        assert!(result.is_err(), "Expected error with invalid token");

        // Error could be Connection/Network if Vault isn't running or HttpStatus if it is
        match result {
            Err(VaultError::HttpStatus(status_code, _)) => {
                assert_eq!(
                    status_code, 403,
                    "Expected 403 Forbidden with invalid token"
                );
            }
            Err(VaultError::Connection(_)) => {
                // This is fine too - means Vault server not running
                println!(
                    "Connection error (Vault not running) - this is expected in standalone tests"
                );
            }
            Err(VaultError::Network(_)) => {
                // This is also fine - means Vault server not running
                println!(
                    "Network error (Vault not running) - this is expected in standalone tests"
                );
            }
            _ => {
                panic!(
                    "Expected VaultError::HttpStatus, VaultError::Connection, or VaultError::Network, got {:?}",
                    result
                );
            }
        }

        Ok(())
    }

    /// Tests the complete transit setup process using a dev Vault instance.
    /// This test verifies that we can:
    /// - Set up a transit engine
    /// - Create a transit key
    /// - Create a transit policy for auto-unseal
    /// - Generate a transit token
    /// - Generate a wrapped transit token
    #[tokio::test]
    async fn test_transit_setup() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();

        let vault_container = setup_vault_container(VaultMode::Dev).await;
        let host = vault_container.get_host().await.unwrap();
        let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
        let vault_url = format!("http://{}:{}", host, host_port);

        wait_for_vault_ready(&vault_url, 10, 1000)
            .await
            .map_err(|e| e.to_string())?;

        // In dev mode, the root token is "root"
        let root_token = "root".to_string();

        // 1. Test setting up transit engine
        info!("Setting up transit engine");
        setup_transit_engine(&vault_url, &root_token).await?;
        info!("Transit engine setup successful");

        // 2. Test creating transit key
        let key_name = "test-key";
        info!("Creating transit key: {}", key_name);
        create_transit_key(&vault_url, &root_token, key_name).await?;
        info!("Created transit key: {}", key_name);

        // 3. Test creating transit policy
        let policy_name = "test-policy";
        info!("Creating transit policy: {}", policy_name);
        create_transit_unseal_policy(&vault_url, &root_token, policy_name, key_name).await?;

        // 4. Test generating transit token
        info!("Generating transit token");
        let token = generate_transit_unseal_token(&vault_url, &root_token, policy_name).await?;
        info!("Generated transit token: {}", token);
        assert!(!token.is_empty(), "Token should not be empty");

        // 5. Test generating wrapped transit token
        info!("Generating wrapped transit token");
        let wrapped_token = generate_wrapped_transit_token(
            &vault_url,
            &root_token,
            policy_name,
            "60s", // 60 second TTL
        )
        .await?;
        info!("Generated wrapped transit token");
        assert!(
            !wrapped_token.is_empty(),
            "Wrapped token should not be empty"
        );

        // Verify all steps completed successfully
        assert!(!token.is_empty(), "Transit token should not be empty");
        assert!(
            !wrapped_token.is_empty(),
            "Wrapped transit token should not be empty"
        );

        Ok(())
    }

    // Test using Docker container with auto-configured settings
    // Run with: cargo test -p merka-vault vault::transit::tests::test_transit_with_real_vault
    #[tokio::test]
    async fn test_transit_with_real_vault() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();

        // Set up a test container for Vault in dev mode
        let vault_container = setup_vault_container(VaultMode::Dev).await;
        let port = vault_container.get_host_port_ipv4(8200).await?;
        let vault_addr = format!("http://127.0.0.1:{}", port);

        // Wait for vault to become available
        wait_for_vault_ready(&vault_addr, 10, 500).await?;

        // Check that vault is initialized and unsealed (dev mode default)
        let status = get_vault_status(&vault_addr).await?;
        assert!(
            status.initialized,
            "Vault should be initialized in dev mode"
        );
        assert!(!status.sealed, "Vault should not be sealed in dev mode");

        // In dev mode, the root token is "root"
        let root_token = "root".to_string();

        // 1. Test setting up transit engine
        let setup_result = setup_transit_engine(&vault_addr, &root_token).await;
        assert!(setup_result.is_ok(), "Transit engine setup should succeed");

        // 2. Test creating transit key
        let key_name = "test-key";
        let create_key_result = create_transit_key(&vault_addr, &root_token, key_name).await;
        assert!(
            create_key_result.is_ok(),
            "Transit key creation should succeed"
        );

        // 3. Test creating transit policy
        let policy_name = "test-policy";
        let create_policy_result =
            create_transit_unseal_policy(&vault_addr, &root_token, policy_name, key_name).await;
        assert!(
            create_policy_result.is_ok(),
            "Transit policy creation should succeed"
        );

        // 4. Test generating transit token
        let token_result =
            generate_transit_unseal_token(&vault_addr, &root_token, policy_name).await;
        assert!(
            token_result.is_ok(),
            "Transit token generation should succeed"
        );

        let token = token_result.unwrap();
        assert!(!token.is_empty(), "Token should not be empty");

        // 5. Test generating wrapped transit token
        let wrapped_token_result = generate_wrapped_transit_token(
            &vault_addr,
            &root_token,
            policy_name,
            "60s", // 60 second TTL
        )
        .await;
        assert!(
            wrapped_token_result.is_ok(),
            "Wrapped transit token generation should succeed"
        );

        let wrapped_token = wrapped_token_result.unwrap();
        assert!(
            !wrapped_token.is_empty(),
            "Wrapped token should not be empty"
        );

        Ok(())
    }
}
