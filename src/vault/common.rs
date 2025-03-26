//! Common helper functions for Vault operations.

use crate::vault::VaultError;
use anyhow::Result;
use reqwest::Response;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

/// Structure representing the seal status of Vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStatusInfo {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
}

/// Detailed status information returned from Vault's seal-status endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStatus {
    #[serde(rename = "type")]
    pub type_field: String,
    pub initialized: bool,
    pub sealed: bool,
    pub t: u8,
    pub n: u8,
    pub progress: u8,
    pub nonce: String,
    pub version: String,
    #[serde(rename = "build_date")]
    pub build_date: String,
    pub migration: bool,
    #[serde(rename = "recovery_seal")]
    pub recovery_seal: bool,
    #[serde(rename = "storage_type")]
    pub storage_type: String,
    #[serde(
        rename = "cluster_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_name: Option<String>,
    #[serde(
        rename = "cluster_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub standby: bool,
}

/// For simplicity, we assume the status endpoint returns the same structure.
#[allow(dead_code)]
pub type StatusResult = VaultStatusInfo;

/// Checks the HTTP response from Vault. If successful, returns the JSON body;
/// otherwise, it extracts an error message or returns the status code.
pub async fn check_response(resp: Response) -> Result<Value, VaultError> {
    let status = resp.status();
    if status.is_success() {
        if status == StatusCode::NO_CONTENT {
            Ok(serde_json::json!({}))
        } else {
            Ok(resp.json().await?)
        }
    } else {
        let body = resp.text().await.unwrap_or_default();
        if let Ok(val) = serde_json::from_str::<Value>(&body) {
            if let Some(errors) = val.get("errors").and_then(|v| v.as_array()) {
                if !errors.is_empty() {
                    if let Some(msg) = errors[0].as_str() {
                        return Err(VaultError::Api(msg.to_string()));
                    }
                }
            }
        }
        Err(VaultError::HttpStatus(status.as_u16(), body))
    }
}

/// Process an HTTP response and deserialize it to the specified type.
/// Handles common status code checks and error conditions.
#[allow(dead_code)]
pub async fn process_response<T: DeserializeOwned>(response: Response) -> Result<T, VaultError> {
    let status = response.status();

    if status.is_success() {
        if status == StatusCode::NO_CONTENT {
            return Err(VaultError::Api("No content received".to_string()));
        }

        let response_body = response
            .json::<T>()
            .await
            .map_err(|e| VaultError::Api(format!("JSON error: {}", e)))?;

        Ok(response_body)
    } else {
        // Get the error text if possible
        let body = response.text().await.unwrap_or_default();

        // Try to parse structured error messages from Vault
        if let Ok(val) = serde_json::from_str::<Value>(&body) {
            if let Some(errors) = val.get("errors").and_then(|v| v.as_array()) {
                if !errors.is_empty() {
                    if let Some(msg) = errors[0].as_str() {
                        return Err(VaultError::Api(msg.to_string()));
                    }
                }
            }
        }

        // Fall back to general HTTP error
        Err(VaultError::HttpStatus(status.as_u16(), body))
    }
}

/// Check if a response indicates success without extracting the body.
/// This is useful for operations where you only care about success/failure.
#[allow(dead_code)]
pub fn check_success_response(response: &Response) -> Result<(), VaultError> {
    let status = response.status();
    if !status.is_success() {
        return Err(VaultError::Api(format!("API error: {}", status)));
    }
    Ok(())
}

/// Sends an authenticated POST request with a JSON payload.
pub async fn auth_post(
    client: &Client,
    token: &str,
    url: &str,
    json_payload: Value,
) -> Result<reqwest::Response, reqwest::Error> {
    client
        .post(url)
        .bearer_auth(token)
        .json(&json_payload)
        .send()
        .await
}

/// Checks Vault's seal status by calling its sys/seal-status endpoint.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL
///
/// # Returns
///
/// A `Result` containing the vault status or an error
pub async fn check_vault_status(vault_addr: &str) -> Result<VaultStatus> {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/sys/seal-status", vault_addr);

    let response = client.get(&url).send().await?;

    // Check if we got a successful response or a 400-level error
    if response.status().is_success() {
        // Normal case - parse the standard response
        let status: VaultStatus = response.json().await?;
        Ok(status)
    } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
        // This might be an uninitialized vault
        // Try to read the error response to confirm
        let error_text = response.text().await?;

        // Check if this is the standard "vault is not initialized" error
        if error_text.contains("Vault is not initialized")
            || error_text.contains("not initialized")
            || error_text.contains("security barrier not initialized")
        {
            // Create a VaultStatus representing an uninitialized vault
            Ok(VaultStatus {
                type_field: "shamir".to_string(),
                initialized: false,
                sealed: true,
                // Set default values for other fields
                t: 0,
                n: 0,
                progress: 0,
                nonce: "".to_string(),
                version: "".to_string(),
                build_date: "".to_string(),
                migration: false,
                recovery_seal: false,
                storage_type: "".to_string(),
                cluster_name: None,
                cluster_id: None,
                standby: false,
            })
        } else {
            // Some other error occurred
            Err(anyhow::anyhow!(
                "Failed to get Vault status: {}",
                error_text
            ))
        }
    } else {
        // Handle other error status codes
        let status = response.status();
        let error_text = response.text().await?;
        Err(anyhow::anyhow!(
            "Failed to get Vault status: {} - {}",
            status,
            error_text
        ))
    }
}

/// Wait for a Vault at `addr` to become unsealed within `timeout`.
pub async fn wait_for_vault_unseal(addr: &str, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        match check_vault_status(addr).await {
            Ok(status) if status.initialized && !status.sealed => {
                info!("Vault at {} is unsealed.", addr);
                return Ok(());
            }
            Ok(status) => {
                info!(
                    "Waiting for Vault at {} (initialized: {}, sealed: {})",
                    addr, status.initialized, status.sealed
                );
            }
            Err(e) => warn!("Error checking Vault status at {}: {}", addr, e),
        }
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Timed out waiting for Vault at {} to unseal",
                addr
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Wait for a Vault at `addr` to become available within `timeout`.
pub async fn wait_for_vault_availability(addr: &str, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    info!("Waiting for Vault at {} to become available...", addr);
    loop {
        let response = reqwest::get(format!("{}/v1/sys/health", addr)).await;

        match response {
            Ok(response) => {
                // Try to parse the response body as text
                match response.text().await {
                    Ok(body) => {
                        if body.contains("initialized") {
                            info!("Vault at {} is available (responding to API calls).", addr);
                            return Ok(());
                        }
                        info!("Vault responded but with unexpected content, continuing to wait...");
                    }
                    Err(_) => {
                        info!("Vault responded but couldn't read body, continuing to wait...");
                    }
                }
            }
            Err(_) => {
                info!("Waiting for Vault at {} to become available...", addr);
            }
        }

        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Timed out waiting for Vault at {} to become available",
                addr
            ));
        }
        sleep(Duration::from_secs(1)).await;
    }
}
