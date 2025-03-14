use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Options for initializing Vault infrastructure.
#[derive(Debug, Serialize)]
pub struct InitOptions {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

/// The response from the Vault native initialization endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct InitResult {
    /// The root token returned by Vault.
    pub root_token: String,
    /// The unseal keys.
    pub keys: Vec<String>,
    /// Optionally, the keys in Base64.
    pub keys_base64: Option<Vec<String>>,
}

/// Structure representing the seal status of Vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStatusInfo {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
}

/// For simplicity, we assume the status endpoint returns the same structure.
pub type StatusResult = VaultStatusInfo;

/// Structure representing the result of an unseal operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResult {
    pub sealed: bool,
    pub progress: u8,
    pub threshold: u8,
    #[serde(default)]
    pub success: bool,
}

/// Initializes Vault by calling its native sys/init endpoint.
pub async fn initialize_vault_infrastructure(
    addr: &str,
    _unused: &str,
    options: InitOptions,
) -> Result<InitResult> {
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

/// Checks Vault’s seal status by calling its sys/seal-status endpoint.
pub async fn check_vault_status(addr: &str, _unused: &str) -> Result<StatusResult> {
    let client = Client::new();
    let url = format!("{}/v1/sys/seal-status", addr);
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| "Failed to send status request")?;
    let result = response
        .json::<StatusResult>()
        .await
        .with_context(|| "Failed to parse status response")?;
    Ok(result)
}

/// Unseals Vault by sending each provided unseal key in sequence.
pub async fn unseal_root_vault(addr: &str, keys: Vec<String>) -> Result<UnsealResult> {
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
