//! Helpers for checking Vault status

use crate::vault::VaultError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStatus {
    pub sealed: bool,
    pub initialized: bool,
    #[serde(default)]
    pub standby: bool,
}

/// Gets the current status of a Vault instance
pub async fn get_vault_status(addr: &str) -> Result<VaultStatus, VaultError> {
    let client = Client::new();
    let status_url = format!("{}/v1/sys/seal-status", addr);

    debug!("Requesting Vault status from {}", status_url);
    let response = match client.get(&status_url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            info!("Failed to connect to Vault at {}: {}", addr, e);
            return Err(VaultError::Connection(e.to_string()));
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|_| "Could not read response body".to_string());
        info!(
            "Vault status request failed with status {}: {}",
            status, text
        );
        return Err(VaultError::Api(format!("HTTP status {}: {}", status, text)));
    }

    let status: VaultStatus = response.json().await.map_err(|e| {
        info!("Failed to parse Vault status response: {}", e);
        VaultError::Parsing(e.to_string())
    })?;

    debug!(
        "Vault status: initialized={}, sealed={}, standby={}",
        status.initialized, status.sealed, status.standby
    );

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;

    #[tokio::test]
    async fn test_get_vault_status_connection_error() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();
        let result = get_vault_status("http://127.0.0.1:9999").await;
        assert!(result.is_err(), "Should fail with connection error");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("error sending request"),
            "Error should be connection-related"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_vault_status_with_real_vault() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();
        let status = get_vault_status("http://127.0.0.1:8200").await?;
        assert!(status.initialized, "Vault should be initialized");
        assert!(!status.sealed, "Vault should not be sealed");
        Ok(())
    }
}
