//! Vault initialization and unsealing operations.
//!
//! This module provides functions to initialize a new Vault server and
//! unseal it for use.

use crate::vault::VaultError;
use anyhow::{Context, Result as AnyhowResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

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
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResult {
    pub sealed: bool,
    pub progress: u8,
    pub threshold: u8,
    #[serde(default)]
    pub success: bool,
}

/// Initializes a new Vault server.
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
    let client = Client::new();
    let url = format!("{}/v1/sys/unseal", addr);
    let mut result: UnsealResult = UnsealResult {
        success: false,
        sealed: true,
        progress: 0,
        threshold: 0,
    };
    for key in keys {
        let response = client
            .post(&url)
            .json(&serde_json::json!({ "key": key }))
            .send()
            .await
            .with_context(|| "Failed to send unseal request")?;
        result = response
            .json::<UnsealResult>()
            .await
            .with_context(|| "Failed to parse unseal response")?;
        if !result.sealed {
            break;
        }
    }
    Ok(result)
}
