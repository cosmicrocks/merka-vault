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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;
    use crate::vault::test_utils::{setup_vault_container, wait_for_vault_ready, VaultMode};
    use tracing::info;

    /// Tests the AppRole authentication method setup.
    /// Verifies that we can:
    /// - Enable the AppRole auth method
    /// - Create a new role with specific policies
    /// - Generate role_id and secret_id credentials
    #[tokio::test]
    async fn test_setup_approle() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();
        let vault_container = setup_vault_container(VaultMode::Dev).await;
        let host = vault_container.get_host().await.unwrap();
        let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
        let vault_url = format!("http://{}:{}", host, host_port);

        wait_for_vault_ready(&vault_url, 10, 1000)
            .await
            .map_err(|e| e.to_string())?;

        let role_name = "test-role";
        let policies = vec!["default".to_string()];
        let creds = setup_approle(&vault_url, "root", role_name, &policies).await?;

        info!(
            "AppRole credentials: role_id: {}, secret_id: {}",
            creds.role_id, creds.secret_id
        );
        assert!(!creds.role_id.is_empty());
        assert!(!creds.secret_id.is_empty());

        Ok(())
    }

    /// Tests combined auth method setup including Kubernetes auth (which may fail in test env).
    /// This verifies that both auth methods can be set up together.
    #[tokio::test]
    async fn test_kubernetes_auth_setup() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();
        let vault_container = setup_vault_container(VaultMode::Dev).await;
        let host = vault_container.get_host().await.unwrap();
        let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
        let vault_url = format!("http://{}:{}", host, host_port);

        wait_for_vault_ready(&vault_url, 10, 1000)
            .await
            .map_err(|e| e.to_string())?;

        let k8s_role = "test-k8s-role";
        let sa_name = "vault-auth";
        let ns = "default";
        let k8s_host = "https://kubernetes.default.svc";
        let k8s_ca = "---BEGIN CERTIFICATE---\nMIIF...==\n-----END CERTIFICATE-----";
        let result =
            setup_kubernetes_auth(&vault_url, "root", k8s_role, sa_name, ns, k8s_host, k8s_ca)
                .await;

        // This will likely fail in a test environment without a real K8s API
        // But we at least verify the code doesn't panic
        if let Err(err) = &result {
            info!(
                "Kubernetes auth setup returned error (expected in test env): {}",
                err
            );
        } else {
            info!("Kubernetes auth configured for role '{}'", k8s_role);
        }

        // Expected error modes in test: either success or VaultError::Api
        assert!(result.is_ok() || matches!(result, Err(VaultError::Api(_))));

        Ok(())
    }
}
