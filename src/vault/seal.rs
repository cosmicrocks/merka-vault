//! Vault sealing operations.
//!
//! This module provides functions for sealing a Vault server.
//! Sealing a Vault makes its data inaccessible until it is unsealed again
//! using the necessary unseal keys or through auto-unseal mechanisms.

use crate::vault::{VaultClient, VaultError};
use tracing::info;

/// Seals a Vault server.
///
/// When a Vault server is sealed, it cannot access its storage backend
/// or perform any operations until it is unsealed again. All data stored
/// in the Vault becomes inaccessible while sealed.
///
/// # Arguments
///
/// * `addr` - The Vault server's URL.
/// * `token` - The authentication token.
///
/// # Returns
///
/// A `Result` indicating success or containing a `VaultError` on failure.
///
/// # Example
///
/// This example is for internal use only and not part of the public API.
/// ```ignore
/// // This is an internal API not meant to be used directly
/// // See the actor API or CLI for how to seal a vault
/// ```
pub async fn seal_vault(addr: &str, token: &str) -> Result<(), VaultError> {
    info!("Sealing vault at {}", addr);

    let client = VaultClient::new(addr, token)?;

    // Send request to seal the vault
    let _ = client
        .put_with_body("/v1/sys/seal", serde_json::json!({}))
        .await?;

    info!("Successfully sealed vault at {}", addr);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;
    use crate::vault::init::unseal_vault;
    use crate::vault::status::get_vault_status;
    use crate::vault::test_utils::{setup_vault_container, VaultMode};

    // Test for invalid token error handling that doesn't require a real Vault
    #[tokio::test]
    async fn test_seal_vault_invalid_token() -> Result<(), Box<dyn std::error::Error>> {
        // Any invalid address/token combination will cause a 403 error
        let invalid_token = "invalid-token";
        let result = seal_vault("http://127.0.0.1:8200", invalid_token).await;

        assert!(result.is_err(), "Expected error with invalid token");

        // Error could be Connection/Network if Vault isn't running or HttpStatus if it is
        match result {
            Err(VaultError::HttpStatus(status_code, _)) => {
                assert_eq!(
                    status_code, 403,
                    "Expected 403 Forbidden with invalid token"
                );
            }
            Err(VaultError::Connection(_)) => {
                // This is fine too - means Vault server not running
                println!(
                    "Connection error (Vault not running) - this is expected in standalone tests"
                );
            }
            Err(VaultError::Network(_)) => {
                // This is also fine - means Vault server not running
                println!(
                    "Network error (Vault not running) - this is expected in standalone tests"
                );
            }
            _ => {
                panic!(
                    "Expected VaultError::HttpStatus, VaultError::Connection, or VaultError::Network, got {:?}",
                    result
                );
            }
        }

        Ok(())
    }

    // Test using Docker container with auto-configured settings
    // Run with: cargo test -p merka-vault vault::seal::tests::test_seal_vault_with_real_vault
    #[tokio::test]
    async fn test_seal_vault_with_real_vault() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();

        // Set up a test container for Vault in regular mode
        let vault_container = setup_vault_container(VaultMode::Regular).await;
        let port = match vault_container.get_host_port_ipv4(8200).await {
            Ok(p) => p,
            Err(e) => {
                return Err(format!("Failed to get container port: {}", e).into());
            }
        };
        let vault_addr = format!("http://127.0.0.1:{}", port);

        // Instead of waiting for vault to be ready with specific status,
        // let's just wait until the container is responsive
        let client = reqwest::Client::new();
        let health_url = format!("{}/v1/sys/health", vault_addr);

        // Wait for the vault container to be responsive
        for attempt in 1..=30 {
            match client.get(&health_url).send().await {
                Ok(_) => {
                    info!("Vault is responsive after {} attempts", attempt);
                    break;
                }
                Err(e) => {
                    info!(
                        "Waiting for Vault to be responsive... attempt {}: {}",
                        attempt, e
                    );
                    if attempt == 30 {
                        return Err(format!(
                            "Vault container not responsive after 30 attempts: {}",
                            e
                        )
                        .into());
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                }
            }
        }

        // In regular mode, we need to initialize Vault first
        use crate::vault::init::init_vault;

        // Initialize the vault with 1 key share for simplicity
        let init_result = match init_vault(&vault_addr, 1, 1, None, None).await {
            Ok(result) => result,
            Err(e) => return Err(format!("Failed to initialize vault: {}", e).into()),
        };
        let root_token = init_result.root_token.clone();
        let unseal_keys = init_result.keys.clone();

        // Unseal the vault using the keys we just got
        if let Err(e) = unseal_vault(&vault_addr, &unseal_keys).await {
            return Err(format!("Failed to unseal vault: {}", e).into());
        }

        // Verify vault is unsealed
        let status = match get_vault_status(&vault_addr).await {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to get vault status: {}", e).into()),
        };
        assert!(status.initialized, "Vault should be initialized");
        assert!(
            !status.sealed,
            "Vault should be unsealed after initialization"
        );

        // Now we can test sealing
        // Seal the vault using the root token
        if let Err(e) = seal_vault(&vault_addr, &root_token).await {
            return Err(format!("Failed to seal vault: {}", e).into());
        }

        // Verify that vault is sealed
        let status = match get_vault_status(&vault_addr).await {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to get vault status after sealing: {}", e).into()),
        };
        assert!(status.sealed, "Vault should be sealed after seal operation");

        // Unseal the vault again using our valid keys
        if let Err(e) = unseal_vault(&vault_addr, &unseal_keys).await {
            return Err(format!("Failed to unseal vault after sealing: {}", e).into());
        }

        // Verify vault is unsealed again
        let status = match get_vault_status(&vault_addr).await {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("Failed to get vault status after unsealing: {}", e).into())
            }
        };
        assert!(
            !status.sealed,
            "Vault should be unsealed after unseal operation"
        );

        Ok(())
    }
}
