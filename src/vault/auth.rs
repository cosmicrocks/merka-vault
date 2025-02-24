//! Authentication setup functions for Vault (AppRole and Kubernetes auth).

use crate::vault::common::check_response;
use crate::vault::{AppRoleCredentials, VaultError};
use reqwest::Client;
use serde_json::json;

/// Sets up AppRole authentication on Vault and returns the Role ID and Secret ID.
pub async fn setup_approle(
    addr: &str,
    token: &str,
    role_name: &str,
    policies: &[String],
) -> Result<AppRoleCredentials, VaultError> {
    let client = Client::new();
    let enable_url = format!("{}/v1/sys/auth/approle", addr);
    let enable_payload = json!({ "type": "approle" });
    client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&enable_payload)
        .send()
        .await?;
    let role_url = format!("{}/v1/auth/approle/role/{}", addr, role_name);
    let policies_str = policies.join(",");
    let role_payload = json!({ "policies": policies_str });
    client
        .post(&role_url)
        .bearer_auth(token)
        .json(&role_payload)
        .send()
        .await?;
    let role_id_url = format!("{}/v1/auth/approle/role/{}/role-id", addr, role_name);
    let resp = client.get(&role_id_url).bearer_auth(token).send().await?;
    let json_resp = check_response(resp).await?;
    let role_id = json_resp
        .get("data")
        .and_then(|d| d.get("role_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let secret_id_url = format!("{}/v1/auth/approle/role/{}/secret-id", addr, role_name);
    let resp = client
        .post(&secret_id_url)
        .bearer_auth(token)
        .send()
        .await?;
    let json_resp = check_response(resp).await?;
    let secret_id = json_resp
        .get("data")
        .and_then(|d| d.get("secret_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(AppRoleCredentials { role_id, secret_id })
}

/// Sets up Kubernetes authentication on Vault.
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
    let enable_url = format!("{}/v1/sys/auth/kubernetes", addr);
    let enable_payload = json!({ "type": "kubernetes" });
    client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&enable_payload)
        .send()
        .await?;
    let config_url = format!("{}/v1/auth/kubernetes/config", addr);
    let config_payload = json!({
        "kubernetes_host": kubernetes_host,
        "kubernetes_ca_cert": kubernetes_ca_cert
    });
    client
        .post(&config_url)
        .bearer_auth(token)
        .json(&config_payload)
        .send()
        .await?;
    let role_url = format!("{}/v1/auth/kubernetes/role/{}", addr, role_name);
    let role_payload = json!({
        "bound_service_account_names": service_account,
        "bound_service_account_namespaces": namespace,
        "policies": "default",
        "ttl": 3600
    });
    client
        .post(&role_url)
        .bearer_auth(token)
        .json(&role_payload)
        .send()
        .await?;
    Ok(())
}
