use crate::vault::common::VaultStatus;
use crate::vault::setup::{SetupResult, VaultSetupConfig};
use crate::vault::{UnsealResult, VaultError};
use async_trait::async_trait;

/// Core Vault operations that both CLI and Actor implementations must support
#[async_trait]
pub trait VaultInterface {
    /// Check the status of the vault
    async fn check_status(&self, addr: &str) -> Result<VaultStatus, VaultError>;

    /// Unseal vault with provided keys
    async fn unseal(&self, addr: &str, keys: Vec<String>) -> Result<UnsealResult, VaultError>;

    /// Setup multi-tier vault with auto-unseal and PKI
    async fn setup(&self, config: VaultSetupConfig) -> Result<SetupResult, VaultError>;
}
