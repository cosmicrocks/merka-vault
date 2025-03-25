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
/// * `token` - The authentication token to use for the sealing operation.
///
/// # Returns
///
/// A `Result` indicating success (`Ok(())`) or containing a `VaultError` on failure.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), merka_vault::vault::VaultError> {
/// use merka_vault::vault::seal_vault;
///
/// let vault_addr = "http://127.0.0.1:8200";
/// let token = "root_token";
///
/// seal_vault(vault_addr, token).await?;
/// # Ok(())
/// # }
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
    use tokio::time::Duration;

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

    // Test with real Vault (optional)
    // Run with: cargo test -p merka-vault vault::seal::tests::test_seal_vault_with_real_vault -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_seal_vault_with_real_vault() -> Result<(), Box<dyn std::error::Error>> {
        init_logging();

        // Connect to a local Vault instance
        let vault_addr = "http://127.0.0.1:8200";
        println!("Connecting to Vault at: {}", vault_addr);

        // Check if Vault is available
        let status = match get_vault_status(vault_addr).await {
            Ok(s) => s,
            Err(e) => {
                println!("Vault status check failed: {}. Is Vault running?", e);
                println!(
                    "This test requires a running Vault instance at {}",
                    vault_addr
                );
                println!("You can start one with: docker run -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 hashicorp/vault:1.13.3");
                return Ok(());
            }
        };

        // Only proceed with test if Vault is initialized and not sealed
        if !status.initialized {
            println!("Vault is not initialized. Skipping test.");
            return Ok(());
        }

        if status.sealed {
            println!("Vault is sealed. Skipping test.");
            return Ok(());
        }

        println!("Vault is initialized and unsealed. Proceeding with test.");

        // In dev mode, the root token is "root"
        let root_token = "root".to_string();

        // Now we can test sealing
        // Seal the vault using the root token
        seal_vault(vault_addr, &root_token).await?;

        // Verify that vault is sealed
        let status = get_vault_status(vault_addr).await?;
        assert!(status.sealed, "Vault should be sealed after seal operation");

        // For test cleanup, unseal the vault again
        // In dev mode, any key works for unsealing
        unseal_vault(vault_addr, &[String::new()]).await?;

        // Verify vault is unsealed again
        let status = get_vault_status(vault_addr).await?;
        assert!(
            !status.sealed,
            "Vault should be unsealed after unseal operation"
        );

        println!("Test completed successfully. Sealing and unsealing verified.");

        Ok(())
    }
}
