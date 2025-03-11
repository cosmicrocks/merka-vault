//! Vault initialization and unsealing operations.
//!
//! This module provides functions to initialize a new Vault server and
//! unseal it for use.

use crate::vault::VaultError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

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
