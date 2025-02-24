//! Trait definitions for Vault operations.
//!
//! This module defines the `VaultOperations` trait that abstracts various Vault methods
//! such as initialization, unsealing, PKI setup, and authentication configuration.

use crate::vault::{InitResult, VaultError};
use async_trait::async_trait;

#[async_trait]
pub trait VaultOperations {
    async fn init_vault(
        &self,
        secret_shares: u8,
        secret_threshold: u8,
    ) -> Result<InitResult, VaultError>;
    async fn unseal_vault(&self, keys: &[String]) -> Result<(), VaultError>;
    async fn setup_pki(
        &self,
        token: &str,
        domain: &str,
        ttl: &str,
        use_intermediate: bool,
        int_addr: Option<&str>,
        int_token: Option<&str>,
    ) -> Result<(String, String), VaultError>;
    async fn setup_approle(
        &self,
        token: &str,
        role_name: &str,
        policies: &[String],
    ) -> Result<crate::vault::AppRoleCredentials, VaultError>;
    async fn setup_kubernetes_auth(
        &self,
        token: &str,
        role_name: &str,
        service_account: &str,
        namespace: &str,
        kubernetes_host: &str,
        kubernetes_ca_cert: &str,
    ) -> Result<(), VaultError>;
    async fn issue_cert(
        &self,
        token: &str,
        domain: &str,
        common_name: &str,
        ttl: &str,
    ) -> Result<String, VaultError>;
}
