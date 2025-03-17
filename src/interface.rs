use crate::vault::common::VaultStatus;
use crate::vault::{UnsealResult, VaultError};
use async_trait::async_trait;

/// Core Vault operations that both CLI and Actor implementations must support
#[async_trait]
pub trait VaultInterface {
    /// Check the status of the vault
    async fn check_status(&self, addr: &str) -> Result<VaultStatus, VaultError>;

    /// Unseal vault with provided keys
    async fn unseal(&self, addr: &str, keys: Vec<String>) -> Result<UnsealResult, VaultError>;

    // Setup root vault
    async fn setup_root(
        &self,
        addr: &str,
        secret_shares: u8,
        secret_threshold: u8,
        key_name: &str,
    ) -> Result<String, VaultError>;

    // Setup sub vault
    async fn setup_sub(
        &self,
        root_addr: &str,
        root_token: &str,
        sub_addr: &str,
        domain: &str,
        ttl: &str,
    ) -> Result<String, VaultError>;

    /// Get an unwrapped transit token for auto-unseal
    async fn get_unwrapped_transit_token(
        &self,
        root_addr: &str,
        root_token: &str,
        key_name: &str,
    ) -> Result<String, VaultError>;
}
