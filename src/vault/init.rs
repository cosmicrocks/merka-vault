//! Vault initialization and unsealing operations.
//!
//! This module provides functions to initialize a new Vault server and
//! unseal it for use.

use crate::vault::status;
use crate::vault::VaultError;
use anyhow::{anyhow, Context, Result as AnyhowResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info, warn};

/// Options for initializing Vault infrastructure.
#[derive(Debug, Serialize)]
pub struct InitOptions {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

/// Request structure for Vault initialization.
#[derive(Serialize)]
struct InitRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_shares: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_threshold: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_shares: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_threshold: Option<u8>,
}

/// Response structure for Vault initialization.
#[derive(Deserialize)]
struct InitResponse {
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    keys_base64: Vec<String>,
    root_token: String,
    #[serde(default)]
    recovery_keys: Option<Vec<String>>,
    #[serde(default)]
    recovery_keys_base64: Option<Vec<String>>,
}

/// Response returned from Vault initialization.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InitResult {
    /// Unseal keys generated during initialization.
    pub keys: Vec<String>,

    /// Unseal keys in Base64 format.
    pub keys_base64: Option<Vec<String>>,

    /// Recovery keys, used in auto-unseal mode.
    pub recovery_keys: Option<Vec<String>>,

    /// Recovery keys in Base64 format.
    pub recovery_keys_base64: Option<Vec<String>>,

    /// Root token for the initialized Vault.
    pub root_token: String,
}

/// Structure representing the result of an unseal operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsealResult {
    pub sealed: bool,
    #[serde(rename = "t", default)]
    pub threshold: u8,
    #[serde(rename = "n", default)]
    pub shares: u8,
    #[serde(default)]
    pub progress: u8,
    #[serde(default)]
    pub success: bool,
}

// Initializes a new Vault server.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL.
/// * `secret_shares` - Number of key shares to split the master key into.
/// * `secret_threshold` - Number of key shares required to reconstruct the master key.
/// * `recovery_shares` - Optional number of recovery key shares for auto-unseal setups.
/// * `recovery_threshold` - Optional number of recovery key threshold for auto-unseal setups.
///
/// # Returns
///
/// A `Result` containing the root token and unseal keys on success, or a `VaultError` on failure.
pub async fn init_vault(
    addr: &str,
    secret_shares: u8,
    secret_threshold: u8,
    recovery_shares: Option<u8>,
    recovery_threshold: Option<u8>,
) -> Result<InitResult, VaultError> {
    let client = Client::new();
    let req = InitRequest {
        secret_shares: if recovery_shares.is_some() {
            None
        } else {
            Some(secret_shares)
        },
        secret_threshold: if recovery_threshold.is_some() {
            None
        } else {
            Some(secret_threshold)
        },
        recovery_shares,
        recovery_threshold,
    };
    let req_url = format!("{}/v1/sys/init", addr);

    let resp = client.put(&req_url).json(&req).send().await?;

    if resp.status().is_success() {
        let init_resp: InitResponse = resp.json().await?;
        Ok(InitResult {
            root_token: init_resp.root_token,
            keys: init_resp.keys,
            keys_base64: Some(init_resp.keys_base64),
            recovery_keys: init_resp.recovery_keys,
            recovery_keys_base64: init_resp.recovery_keys_base64,
        })
    } else {
        Err(VaultError::ApiError(format!(
            "Failed to initialize Vault: {}",
            resp.text().await?
        )))
    }
}

/// Initializes Vault by calling the native sys/init endpoint.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL
/// * `options` - Initialization options including shares and threshold
///
/// # Returns
///
/// A `Result` containing the initialization response or an error
pub async fn initialize_vault_infrastructure(
    addr: &str,
    options: InitOptions,
) -> AnyhowResult<InitResult> {
    let client = Client::new();
    let url = format!("{}/v1/sys/init", addr);
    let payload = serde_json::json!({
        "secret_shares": options.secret_shares,
        "secret_threshold": options.secret_threshold
    });
    let response = client
        .put(&url)
        .json(&payload)
        .send()
        .await
        .with_context(|| "Failed to send init request")?;
    let result = response
        .json::<InitResult>()
        .await
        .with_context(|| "Failed to parse init response")?;
    Ok(result)
}

/// Unseals a Vault server.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL.
/// * `keys` - The unseal keys to use.
///
/// # Returns
///
/// A `Result` indicating success or containing a `VaultError` on failure.
pub async fn unseal_vault(addr: &str, keys: &[String]) -> Result<(), VaultError> {
    let client = Client::new();
    let req_url = format!("{}/v1/sys/unseal", addr);

    for key in keys {
        let resp = client
            .put(&req_url)
            .json(&json!({ "key": key }))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(VaultError::ApiError(format!(
                "Failed to unseal Vault: {}",
                resp.text().await?
            )));
        }
    }

    Ok(())
}

/// Unseals Vault by sending each provided unseal key in sequence.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL
/// * `keys` - Vector of unseal keys to use
///
/// # Returns
///
/// A `Result` containing the unseal status or an error
pub async fn unseal_root_vault(addr: &str, keys: Vec<String>) -> AnyhowResult<UnsealResult> {
    info!("Unsealing vault at {} with {} keys", addr, keys.len());
    let client = Client::new();
    let unseal_url = format!("{}/v1/sys/unseal", addr);

    // Check current seal status first
    match status::get_vault_status(addr).await {
        Ok(status) => {
            if !status.sealed {
                info!("Vault at {} is already unsealed", addr);
                return Ok(UnsealResult {
                    sealed: false,
                    threshold: 0,
                    shares: 0,
                    progress: 0,
                    success: true,
                });
            }
            info!("Vault is sealed, proceeding with unsealing...");
        }
        Err(e) => warn!("Could not check seal status: {}", e),
    }

    let mut last_result: Option<UnsealResult> = None;

    // Only use the threshold number of keys (normally 3)
    let threshold_keys = keys.iter().take(3);

    for key in threshold_keys {
        debug!("Sending unseal request with key to {}", unseal_url);
        let unseal_response = client
            .put(&unseal_url)
            .json(&json!({ "key": key }))
            .send()
            .await?;

        if !unseal_response.status().is_success() {
            let status = unseal_response.status();
            let text = unseal_response.text().await?;
            error!(
                "Unseal operation failed. Status: {}, Body: {}",
                status, text
            );
            return Err(anyhow!(
                "Failed to unseal Vault: HTTP {} - {}",
                status,
                text
            ));
        }

        let unseal_result: UnsealResult = unseal_response.json().await?;
        last_result = Some(unseal_result.clone());

        info!(
            "Unseal progress: sealed={}, threshold={}, shares={}, progress={}",
            unseal_result.sealed,
            unseal_result.threshold,
            unseal_result.shares,
            unseal_result.progress
        );

        if !unseal_result.sealed {
            info!("Vault unsealed successfully!");
            break;
        }
    }

    match last_result {
        Some(result) if !result.sealed => {
            info!("Vault unsealing completed successfully");
            Ok(result)
        }
        Some(result) => {
            warn!(
                "Vault still sealed after applying threshold keys. Progress: {}/{}",
                result.progress, result.threshold
            );
            Ok(result)
        }
        None => {
            error!("No unseal operations were performed");
            Err(anyhow!("No unseal operations were performed"))
        }
    }
}

pub async fn initialize_vault(addr: &str) -> AnyhowResult<InitResult> {
    info!("Initializing vault at {}", addr);
    let client = Client::new();
    let init_url = format!("{}/v1/sys/init", addr);

    // Check if already initialized
    match status::get_vault_status(addr).await {
        Ok(status) if status.initialized => {
            info!("Vault at {} is already initialized", addr);
            return Err(anyhow!("Vault is already initialized"));
        }
        Ok(_) => info!("Vault not yet initialized, proceeding..."),
        Err(e) => warn!("Could not check initialization status: {}", e),
    }

    debug!("Sending initialization request to {}", init_url);
    let init_response = client
        .put(&init_url)
        .json(&json!({
            "secret_shares": 5,
            "secret_threshold": 3
        }))
        .send()
        .await?;

    if !init_response.status().is_success() {
        let status = init_response.status();
        let text = init_response.text().await?;
        error!(
            "Vault initialization failed. Status: {}, Body: {}",
            status, text
        );
        return Err(anyhow!(
            "Failed to initialize Vault: HTTP {} - {}",
            status,
            text
        ));
    }

    let init_result: InitResult = init_response.json().await?;
    info!(
        "Vault initialized successfully with {} keys",
        init_result.keys.len()
    );

    Ok(init_result)
}

/// Seals a Vault server.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL.
/// * `token` - The authentication token.
///
/// # Returns
///
/// A `Result` indicating success or containing a `VaultError` on failure.
pub async fn seal_vault(addr: &str, token: &str) -> Result<(), VaultError> {
    let client = Client::new();
    let req_url = format!("{}/v1/sys/seal", addr);

    let resp = client.post(&req_url).bearer_auth(token).send().await?;

    if !resp.status().is_success() {
        return Err(VaultError::ApiError(format!(
            "Failed to seal Vault: {}",
            resp.text().await?
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;

    use crate::vault::test_utils::{setup_vault_container, wait_for_vault_ready, VaultMode};
    use tracing::info;

    #[tokio::test]
    async fn test_init_with_invalid_params() -> Result<(), Box<dyn std::error::Error>> {
        // Test with invalid parameters
        let vault_addr = "http://127.0.0.1:8200";

        // Try to initialize with invalid parameters (threshold > shares)
        let init_result = init_vault(
            vault_addr, 2, // secret_shares
            3, // secret_threshold (invalid: threshold > shares)
            None, None,
        )
        .await;

        // This should fail
        assert!(
            init_result.is_err(),
            "Should fail with invalid threshold > shares"
        );

        // Check for connection errors
        let init_result = init_vault(
            "http://127.0.0.1:9999", // Invalid address
            1,
            1,
            None,
            None,
        )
        .await;

        assert!(init_result.is_err(), "Should fail with connection error");

        Ok(())
    }

    /// Tests that initialization fails on a development mode Vault instance.
    /// Dev mode Vaults are pre-initialized and unsealed, so this test confirms that
    /// our init function properly detects this condition and returns an error.
    #[tokio::test]
    async fn test_vault_init_and_unseal_dev_mode() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();
        let vault_container = setup_vault_container(VaultMode::Dev).await;
        let host = vault_container.get_host().await.unwrap();
        let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
        let vault_url = format!("http://{}:{}", host, host_port);

        // Give the container more time to fully start up and be ready
        info!("Waiting for Vault dev container to start up...");
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Increase retries and timeout for container readiness
        wait_for_vault_ready(&vault_url, 30, 1000)
            .await
            .map_err(|e| e.to_string())?;

        // Dev mode vaults are already initialized, so this should fail
        assert!(init_vault(&vault_url, 1, 1, None, None).await.is_err());

        Ok(())
    }
}
