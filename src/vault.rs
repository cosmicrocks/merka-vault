use reqwest::{Client, StatusCode};
use serde_json::Value;
use thiserror::Error;

use crate::AppRoleCredentials;

/// Custom error type for Vault operations
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Vault API error: {0}")]
    Api(String),
    #[error("Vault returned error status: {0}")]
    HttpStatus(StatusCode),
    #[error("Vault not initialized or sealed")]
    NotInitialized,
}

/// Internal helper to check a Vault HTTP response for success or extract errors
async fn check_response(resp: reqwest::Response) -> Result<Value, VaultError> {
    let status = resp.status();
    if status.is_success() {
        if status == StatusCode::NO_CONTENT {
            // No content (204) – return empty JSON object
            return Ok(serde_json::json!({}));
        }
        // Parse JSON body
        let json_val: Value = resp.json().await?;
        Ok(json_val)
    } else {
        // Try to parse error message from Vault
        let body = resp.text().await.unwrap_or_default();
        if let Ok(val) = serde_json::from_str::<Value>(&body) {
            if let Some(errors) = val.get("errors") {
                if errors.is_array() && !errors.as_array().unwrap().is_empty() {
                    if let Some(msg) = errors[0].as_str() {
                        return Err(VaultError::Api(msg.to_string()));
                    }
                }
            }
        }
        // Fallback to status code if no JSON error message
        Err(VaultError::HttpStatus(status))
    }
}

/// Initialize a new Vault server (returns unseal keys and root token).
pub async fn init_vault(
    addr: &str,
    secret_shares: u8,
    secret_threshold: u8,
) -> Result<crate::actor::InitResult, VaultError> {
    // Endpoint: POST /v1/sys/init
    let url = format!("{}/v1/sys/init", addr);
    let payload = serde_json::json!({
        "secret_shares": secret_shares,
        "secret_threshold": secret_threshold
    });
    let client = Client::new();
    let resp = client.post(&url).json(&payload).send().await?;
    let json = check_response(resp).await?;
    // Parse out root token and unseal keys
    let root_token = json
        .get("root_token")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // Vault may return keys in "keys_base64" (base64 encoded) or "keys"
    let keys_array = if json.get("keys_base64").is_some() {
        json["keys_base64"].as_array().unwrap()
    } else {
        json["keys"].as_array().unwrap()
    };
    let keys: Vec<String> = keys_array
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    Ok(crate::actor::InitResult { root_token, keys })
}

/// Unseal the Vault by providing all necessary unseal keys.
pub async fn unseal_vault(addr: &str, keys: &[String]) -> Result<(), VaultError> {
    // Endpoint: POST /v1/sys/unseal (called multiple times until sealed=false)
    let url = format!("{}/v1/sys/unseal", addr);
    let client = Client::new();
    for (i, key) in keys.iter().enumerate() {
        let payload = serde_json::json!({ "key": key });
        let resp = client.post(&url).json(&payload).send().await?;
        let json = check_response(resp).await?;
        // Check if Vault is unsealed now
        if let Some(false) = json.get("sealed").and_then(|v| v.as_bool()) {
            break;
        }
        // If we've provided all keys and it's still sealed, that's an error
        if i == keys.len() - 1 {
            return Err(VaultError::Api(
                "Vault is still sealed after provided keys".into(),
            ));
        }
    }
    Ok(())
}

/// Enable and configure the PKI secrets engine, generate a root CA, and create a role.
/// Returns the root certificate (PEM) and the name of the role created.
pub async fn setup_pki(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<(String, String), VaultError> {
    let client = Client::new();
    // 1. Enable the PKI engine at path "pki"
    let enable_url = format!("{}/v1/sys/mounts/pki", addr);
    let payload = serde_json::json!({ "type": "pki" });
    let resp = client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await?;
    check_response(resp).await?; // expect 204 or empty JSON on success

    // 2. Tune the max lease TTL for the PKI (e.g., 1 year)
    let tune_url = format!("{}/v1/sys/mounts/pki/tune", addr);
    let tune_payload = serde_json::json!({ "max_lease_ttl": ttl });
    let resp = client
        .post(&tune_url)
        .bearer_auth(token)
        .json(&tune_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success

    // 3. Generate a self-signed internal root certificate
    let gen_url = format!("{}/v1/pki/root/generate/internal", addr);
    let gen_payload = serde_json::json!({ "common_name": common_name, "ttl": ttl });
    let resp = client
        .post(&gen_url)
        .bearer_auth(token)
        .json(&gen_payload)
        .send()
        .await?;
    let json = check_response(resp).await?;
    // The generated certificate is usually under "data.certificate"
    let cert = json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .or_else(|| json.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // 4. Configure certificate URLs (issuing cert and CRL distribution) for completeness
    let urls_url = format!("{}/v1/pki/config/urls", addr);
    let issuing_urls = format!("{}/v1/pki/ca", addr);
    let crl_urls = format!("{}/v1/pki/crl", addr);
    let urls_payload = serde_json::json!({
        "issuing_certificates": issuing_urls,
        "crl_distribution_points": crl_urls
    });
    let resp = client
        .post(&urls_url)
        .bearer_auth(token)
        .json(&urls_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success

    // 5. Create a default role to allow issuing certificates for the common_name
    // Role name derived from common_name (replace dots with hyphens)
    let role_name = common_name.replace('.', "-");
    let role_url = format!("{}/v1/pki/roles/{}", addr, role_name);
    let role_payload = serde_json::json!({
        "allowed_domains": common_name,
        "allow_subdomains": true,
        "max_ttl": ttl
    });
    let resp = client
        .post(&role_url)
        .bearer_auth(token)
        .json(&role_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success

    Ok((cert, role_name))
}

/// Enable AppRole auth method and create a new AppRole with given policies.
/// Returns the generated RoleID and SecretID for the AppRole.
pub async fn setup_approle(
    addr: &str,
    token: &str,
    role_name: &str,
    policies: &[String],
) -> Result<AppRoleCredentials, VaultError> {
    let client = Client::new();
    // 1. Enable the AppRole auth method at path "approle"
    let enable_url = format!("{}/v1/sys/auth/approle", addr);
    let enable_payload = serde_json::json!({ "type": "approle" });
    let resp = client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&enable_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success (or 400 if already enabled)

    // 2. Create the AppRole with specified policies
    let role_url = format!("{}/v1/auth/approle/role/{}", addr, role_name);
    let policies_str = policies.join(",");
    let role_payload = serde_json::json!({ "policies": policies_str });
    let resp = client
        .post(&role_url)
        .bearer_auth(token)
        .json(&role_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success

    // 3. Fetch the RoleID
    let role_id_url = format!("{}/v1/auth/approle/role/{}/role-id", addr, role_name);
    let resp = client.get(&role_id_url).bearer_auth(token).send().await?;
    let json = check_response(resp).await?;
    let role_id = json
        .get("data")
        .and_then(|d| d.get("role_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // 4. Generate a new SecretID for the AppRole
    let secret_id_url = format!("{}/v1/auth/approle/role/{}/secret-id", addr, role_name);
    let resp = client
        .post(&secret_id_url)
        .bearer_auth(token)
        .send()
        .await?;
    let json = check_response(resp).await?;
    let secret_id = json
        .get("data")
        .and_then(|d| d.get("secret_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(AppRoleCredentials { role_id, secret_id })
}

/// Enable Kubernetes auth method and configure a role for a Kubernetes service account.
pub async fn setup_kubernetes_auth(
    addr: &str,
    token: &str,
    role_name: &str,
    service_account: &str,
    namespace: &str,
    kubernetes_host: &str,
    kubernetes_ca_cert: &str,
) -> Result<(), VaultError> {
    let client = Client::new();
    // 1. Enable the Kubernetes auth method at path "kubernetes"
    let enable_url = format!("{}/v1/sys/auth/kubernetes", addr);
    let enable_payload = serde_json::json!({ "type": "kubernetes" });
    let resp = client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&enable_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success

    // 2. Configure Vault's Kubernetes auth with the cluster endpoint and CA cert.
    // (Note: A token_reviewer_jwt would normally be needed for Vault to authenticate with K8s.
    // Here we assume Vault is running inside the cluster with its own SA token, or this is set via env.)
    let config_url = format!("{}/v1/auth/kubernetes/config", addr);
    let config_payload = serde_json::json!({
        "kubernetes_host": kubernetes_host,
        "kubernetes_ca_cert": kubernetes_ca_cert
        // "token_reviewer_jwt": "<JWT>" // omitted for simplicity or assumed via environment
    });
    let resp = client
        .post(&config_url)
        .bearer_auth(token)
        .json(&config_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success (could error if JWT is required and missing)

    // 3. Create a role binding a Kubernetes Service Account to Vault policies
    let role_url = format!("{}/v1/auth/kubernetes/role/{}", addr, role_name);
    let role_payload = serde_json::json!({
        "bound_service_account_names": service_account,
        "bound_service_account_namespaces": namespace,
        "policies": "default",        // attach 'default' policy or any other existing policy
        "ttl": 3600
    });
    let resp = client
        .post(&role_url)
        .bearer_auth(token)
        .json(&role_payload)
        .send()
        .await?;
    check_response(resp).await?; // 204 on success

    Ok(())
}
