//! vault.rs – Module for configuring HashiCorp Vault via its REST API.

use reqwest::{Client, StatusCode};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Vault API error: {0}")]
    Api(String),
    #[error("Vault returned HTTP status: {0}")]
    HttpStatus(StatusCode),
}

pub struct InitResult {
    pub root_token: String,
    pub keys: Vec<String>,
}

pub struct AppRoleCredentials {
    pub role_id: String,
    pub secret_id: String,
}

/// ----------------------------
/// Vault Initialization & Unseal
/// ----------------------------

pub async fn init_vault(
    addr: &str,
    secret_shares: u8,
    secret_threshold: u8,
) -> Result<InitResult, VaultError> {
    let url = format!("{}/v1/sys/init", addr);
    let payload = serde_json::json!({
        "secret_shares": secret_shares,
        "secret_threshold": secret_threshold
    });
    let client = Client::new();
    let resp = client.post(&url).json(&payload).send().await?;
    let json = check_response(resp).await?;
    let root_token = json
        .get("root_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let keys_array = if json.get("keys_base64").is_some() {
        json["keys_base64"].as_array().unwrap()
    } else {
        json["keys"].as_array().unwrap()
    };
    let keys = keys_array
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    Ok(InitResult { root_token, keys })
}

pub async fn unseal_vault(addr: &str, keys: &[String]) -> Result<(), VaultError> {
    let url = format!("{}/v1/sys/unseal", addr);
    let client = Client::new();
    for (i, key) in keys.iter().enumerate() {
        let payload = serde_json::json!({ "key": key });
        let resp = client.post(&url).json(&payload).send().await?;
        let json = check_response(resp).await?;
        if let Some(sealed) = json.get("sealed").and_then(|v| v.as_bool()) {
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

/// ----------------------------
/// PKI Setup
/// ----------------------------

/// Configures a Vault as the root PKI engine.
pub async fn setup_pki_root(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<String, VaultError> {
    let client = Client::new();

    // Mount and tune the PKI engine at "pki".
    let mount_url = format!("{}/v1/sys/mounts/pki", addr);
    auth_post(
        &client,
        token,
        &mount_url,
        serde_json::json!({ "type": "pki" }),
    )
    .await?;
    let tune_url = format!("{}/v1/sys/mounts/pki/tune", addr);
    auth_post(
        &client,
        token,
        &tune_url,
        serde_json::json!({ "max_lease_ttl": ttl }),
    )
    .await?;

    // Generate a self‑signed root certificate.
    let gen_url = format!("{}/v1/pki/root/generate/internal", addr);
    let gen_payload = serde_json::json!({ "common_name": common_name, "ttl": ttl });
    let resp = auth_post(&client, token, &gen_url, gen_payload).await?;
    let json = check_response(resp).await?;
    let cert = json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Configure issuing and CRL URLs.
    let urls_url = format!("{}/v1/pki/config/urls", addr);
    let urls_payload = serde_json::json!({
        "issuing_certificates": format!("{}/v1/pki/ca", addr),
        "crl_distribution_points": format!("{}/v1/pki/crl", addr)
    });
    auth_post(&client, token, &urls_url, urls_payload).await?;

    // Create a role (role name is derived from the common name).
    let role_name = common_name.replace('.', "-");
    let role_url = format!("{}/v1/pki/roles/{}", addr, role_name);
    let role_payload = serde_json::json!({
        "allowed_domains": common_name,
        "allow_subdomains": true,
        "max_ttl": ttl
    });
    auth_post(&client, token, &role_url, role_payload).await?;

    Ok(cert)
}

/// Configures an intermediate Vault using the root Vault to sign its CSR.
/// Requires the intermediate Vault’s own token.
pub async fn setup_pki_intermediate(
    root_addr: &str,
    root_token: &str,
    int_addr: &str,
    int_token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<(String, String), VaultError> {
    let client = Client::new();

    // Configure root Vault and get its certificate.
    let root_cert = setup_pki_root(root_addr, root_token, common_name, ttl).await?;

    // Configure the intermediate Vault.
    let int_mount = "pki";
    let int_mount_url = format!("{}/v1/sys/mounts/{}", int_addr, int_mount);
    auth_post(
        &client,
        int_token,
        &int_mount_url,
        serde_json::json!({ "type": "pki" }),
    )
    .await?;
    let int_tune_url = format!("{}/v1/sys/mounts/{}/tune", int_addr, int_mount);
    auth_post(
        &client,
        int_token,
        &int_tune_url,
        serde_json::json!({ "max_lease_ttl": ttl }),
    )
    .await?;

    // Generate a CSR on the intermediate Vault.
    let csr_url = format!(
        "{}/v1/{}/intermediate/generate/internal",
        int_addr, int_mount
    );
    let csr_payload = serde_json::json!({ "common_name": common_name, "ttl": ttl });
    let csr_resp = auth_post(&client, int_token, &csr_url, csr_payload).await?;
    let csr_json = check_response(csr_resp).await?;
    let csr = csr_json
        .get("data")
        .and_then(|d| d.get("csr"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Sign the intermediate CSR using the root Vault.
    let sign_url = format!("{}/v1/pki/root/sign-intermediate", root_addr);
    let sign_payload = serde_json::json!({
        "csr": csr,
        "common_name": common_name,
        "ttl": ttl,
        "format": "pem_bundle"
    });
    let sign_resp = auth_post(&client, root_token, &sign_url, sign_payload).await?;
    let sign_json = check_response(sign_resp).await?;
    let signed_cert = sign_json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Set the signed certificate on the intermediate Vault.
    let set_url = format!("{}/v1/{}/intermediate/set-signed", int_addr, int_mount);
    auth_post(
        &client,
        int_token,
        &set_url,
        serde_json::json!({ "certificate": signed_cert }),
    )
    .await?;

    // Configure URLs on the intermediate Vault.
    let int_urls_url = format!("{}/v1/{}/config/urls", int_addr, int_mount);
    let int_urls_payload = serde_json::json!({
        "issuing_certificates": format!("{}/v1/{}/ca", int_addr, int_mount),
        "crl_distribution_points": format!("{}/v1/{}/crl", int_addr, int_mount)
    });
    auth_post(&client, int_token, &int_urls_url, int_urls_payload).await?;

    // Create a role on the intermediate Vault.
    let role_name = format!("{}-int", common_name.replace('.', "-"));
    let role_url = format!("{}/v1/{}/roles/{}", int_addr, int_mount, role_name);
    let role_payload = serde_json::json!({
        "allowed_domains": common_name,
        "allow_subdomains": true,
        "max_ttl": ttl
    });
    auth_post(&client, int_token, &role_url, role_payload).await?;

    let cert_chain = format!("{}\n{}", signed_cert, root_cert);
    Ok((cert_chain, role_name))
}

/// Configures a Vault in "same vault" mode using two mounts on the same server.
pub async fn setup_pki_same_vault(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<(String, String), VaultError> {
    let client = Client::new();
    let mount_root = "pki_root";
    let mount_int = "pki";

    // Configure the root mount.
    let root_mount_url = format!("{}/v1/sys/mounts/{}", addr, mount_root);
    auth_post(
        &client,
        token,
        &root_mount_url,
        serde_json::json!({ "type": "pki" }),
    )
    .await?;
    let tune_root_url = format!("{}/v1/sys/mounts/{}/tune", addr, mount_root);
    auth_post(
        &client,
        token,
        &tune_root_url,
        serde_json::json!({ "max_lease_ttl": ttl }),
    )
    .await?;
    let root_url = format!("{}/v1/{}/root/generate/internal", addr, mount_root);
    let root_payload = serde_json::json!({ "common_name": common_name, "ttl": ttl });
    let root_resp = auth_post(&client, token, &root_url, root_payload).await?;
    let root_json = check_response(root_resp).await?;
    let root_cert = root_json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let root_urls_url = format!("{}/v1/{}/config/urls", addr, mount_root);
    auth_post(
        &client,
        token,
        &root_urls_url,
        serde_json::json!({
            "issuing_certificates": format!("{}/v1/{}/ca", addr, mount_root),
            "crl_distribution_points": format!("{}/v1/{}/crl", addr, mount_root)
        }),
    )
    .await?;

    // Configure the intermediate mount.
    let int_mount_url = format!("{}/v1/sys/mounts/{}", addr, mount_int);
    auth_post(
        &client,
        token,
        &int_mount_url,
        serde_json::json!({ "type": "pki" }),
    )
    .await?;
    let tune_int_url = format!("{}/v1/sys/mounts/{}/tune", addr, mount_int);
    auth_post(
        &client,
        token,
        &tune_int_url,
        serde_json::json!({ "max_lease_ttl": ttl }),
    )
    .await?;
    let csr_url = format!("{}/v1/{}/intermediate/generate/internal", addr, mount_int);
    let csr_payload = serde_json::json!({ "common_name": common_name, "ttl": ttl });
    let csr_resp = auth_post(&client, token, &csr_url, csr_payload).await?;
    let csr_json = check_response(csr_resp).await?;
    let csr = csr_json
        .get("data")
        .and_then(|d| d.get("csr"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let sign_url = format!("{}/v1/{}/root/sign-intermediate", addr, mount_root);
    let sign_payload = serde_json::json!({
        "csr": csr,
        "common_name": common_name,
        "ttl": ttl,
        "format": "pem_bundle"
    });
    let sign_resp = auth_post(&client, token, &sign_url, sign_payload).await?;
    let sign_json = check_response(sign_resp).await?;
    let signed_cert = sign_json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let set_url = format!("{}/v1/{}/intermediate/set-signed", addr, mount_int);
    auth_post(
        &client,
        token,
        &set_url,
        serde_json::json!({ "certificate": signed_cert }),
    )
    .await?;
    let int_urls_url = format!("{}/v1/{}/config/urls", addr, mount_int);
    auth_post(
        &client,
        token,
        &int_urls_url,
        serde_json::json!({
            "issuing_certificates": format!("{}/v1/{}/ca", addr, mount_int),
            "crl_distribution_points": format!("{}/v1/{}/crl", addr, mount_int)
        }),
    )
    .await?;
    let role_name = common_name.replace('.', "-");
    let role_url = format!("{}/v1/{}/roles/{}", addr, mount_int, role_name);
    auth_post(
        &client,
        token,
        &role_url,
        serde_json::json!({
            "allowed_domains": common_name,
            "allow_subdomains": true,
            "max_ttl": ttl
        }),
    )
    .await?;
    let cert_chain = format!("{}\n{}", signed_cert, root_cert);
    Ok((cert_chain, role_name))
}

/// Wrapper for PKI setup that matches the actor API.
/// If `intermediate` is false, it uses root‑only setup.
/// If true and an intermediate address is provided, it uses separate intermediate mode.
/// Otherwise, it uses same‑vault mode.
pub async fn setup_pki(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
    intermediate: bool,
    intermediate_addr: Option<&str>,
    int_token: Option<&str>,
) -> Result<(String, String), VaultError> {
    if !intermediate {
        let cert = setup_pki_root(addr, token, common_name, ttl).await?;
        let role_name = common_name.replace('.', "-");
        Ok((cert, role_name))
    } else if let Some(int_addr) = intermediate_addr {
        if let Some(itoken) = int_token {
            setup_pki_intermediate(addr, token, int_addr, itoken, common_name, ttl).await
        } else {
            Err(VaultError::Api(
                "Intermediate setup requires both address and token".into(),
            ))
        }
    } else {
        // same vault mode: no intermediate address provided.
        setup_pki_same_vault(addr, token, common_name, ttl).await
    }
}

/// ----------------------------
/// AppRole and Kubernetes Auth
/// ----------------------------

pub async fn setup_approle(
    addr: &str,
    token: &str,
    role_name: &str,
    policies: &[String],
) -> Result<AppRoleCredentials, VaultError> {
    let client = Client::new();
    let enable_url = format!("{}/v1/sys/auth/approle", addr);
    let enable_payload = serde_json::json!({ "type": "approle" });
    client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&enable_payload)
        .send()
        .await?;
    let role_url = format!("{}/v1/auth/approle/role/{}", addr, role_name);
    let policies_str = policies.join(",");
    let role_payload = serde_json::json!({ "policies": policies_str });
    client
        .post(&role_url)
        .bearer_auth(token)
        .json(&role_payload)
        .send()
        .await?;
    let role_id_url = format!("{}/v1/auth/approle/role/{}/role-id", addr, role_name);
    let resp = client.get(&role_id_url).bearer_auth(token).send().await?;
    let json = check_response(resp).await?;
    let role_id = json
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
    let json = check_response(resp).await?;
    let secret_id = json
        .get("data")
        .and_then(|d| d.get("secret_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(AppRoleCredentials { role_id, secret_id })
}

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
    let enable_payload = serde_json::json!({ "type": "kubernetes" });
    client
        .post(&enable_url)
        .bearer_auth(token)
        .json(&enable_payload)
        .send()
        .await?;
    let config_url = format!("{}/v1/auth/kubernetes/config", addr);
    let config_payload = serde_json::json!({
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
    let role_payload = serde_json::json!({
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

/// ----------------------------
/// Internal Helpers
/// ----------------------------

async fn check_response(resp: reqwest::Response) -> Result<Value, VaultError> {
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
        Err(VaultError::HttpStatus(status))
    }
}

async fn auth_post(
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
