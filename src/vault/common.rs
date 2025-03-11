//! Common helper functions for Vault operations.

use crate::vault::VaultError;
use reqwest::StatusCode;
use reqwest::{Client, Response};
use serde_json::Value;

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
