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
