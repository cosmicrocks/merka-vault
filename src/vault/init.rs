//! Initialization and unseal functions for Vault.

use crate::vault::common::check_response;
use crate::vault::{InitResult, VaultError};
use reqwest::Client;
use serde_json::json;

/// Initializes Vault with the given secret shares and threshold.
/// Returns an `InitResult` containing the root token and unseal keys.
pub async fn init_vault(
    addr: &str,
    secret_shares: u8,
    secret_threshold: u8,
) -> Result<InitResult, VaultError> {
    let url = format!("{}/v1/sys/init", addr);
    let payload = json!({
        "secret_shares": secret_shares,
        "secret_threshold": secret_threshold
    });
    let client = Client::new();
    let resp = client.post(&url).json(&payload).send().await?;
    let json_resp = check_response(resp).await?;
    let root_token = json_resp
        .get("root_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let keys_array = if json_resp.get("keys_base64").is_some() {
        json_resp["keys_base64"].as_array().unwrap()
    } else {
        json_resp["keys"].as_array().unwrap()
    };
    let keys = keys_array
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    Ok(InitResult { root_token, keys })
}

/// Unseals the Vault by sending each unseal key until the server is unsealed.
pub async fn unseal_vault(addr: &str, keys: &[String]) -> Result<(), VaultError> {
    let url = format!("{}/v1/sys/unseal", addr);
    let client = Client::new();
    for (i, key) in keys.iter().enumerate() {
        let payload = json!({ "key": key });
        let resp = client.post(&url).json(&payload).send().await?;
        let json_resp = check_response(resp).await?;
        if let Some(sealed) = json_resp.get("sealed").and_then(|v| v.as_bool()) {
            if !sealed {
                break;
            }
        }
        if i == keys.len() - 1 {
            return Err(VaultError::Api(
                "Vault is still sealed after provided keys".into(),
            ));
        }
    }
    Ok(())
}
