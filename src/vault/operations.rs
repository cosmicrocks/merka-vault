//! Trait definitions for Vault operations.
//!
//! This module defines traits that abstract Vault operations,
//! enabling different implementations such as direct API calls
//! or actor-based approaches.

use crate::vault::{AppRoleCredentials, InitResult, VaultError};
use async_trait::async_trait;

/// Trait defining core Vault operations.
///
/// This trait abstracts the operations that can be performed against a Vault server,
/// allowing for different implementations (direct, actor-based, etc.)
#[allow(dead_code)]
#[async_trait]
pub trait VaultOperations {
    /// Initialize a new Vault instance with the specified key shares and threshold.
    async fn init_vault(
        &self,
        secret_shares: u8,
        secret_threshold: u8,
    ) -> Result<InitResult, VaultError>;

    /// Unseal a Vault instance using the provided unseal keys.
    async fn unseal_vault(&self, keys: &[String]) -> Result<(), VaultError>;

    /// Set up a PKI infrastructure in Vault.
    async fn setup_pki(
        &self,
        token: &str,
        domain: &str,
        ttl: &str,
        use_intermediate: bool,
        int_addr: Option<&str>,
        int_token: Option<&str>,
    ) -> Result<(String, String), VaultError>;

    /// Set up AppRole authentication in Vault.
    async fn setup_approle(
        &self,
        token: &str,
        role_name: &str,
        policies: &[String],
    ) -> Result<AppRoleCredentials, VaultError>;

    /// Set up Kubernetes authentication in Vault.
    async fn setup_kubernetes_auth(
        &self,
        token: &str,
        role_name: &str,
        service_account: &str,
        namespace: &str,
        kubernetes_host: &str,
        kubernetes_ca_cert: &str,
    ) -> Result<(), VaultError>;

    /// Issue a certificate from the PKI secrets engine.
    async fn issue_certificate(
        &self,
        token: &str,
        domain: &str,
        common_name: &str,
        ttl: &str,
    ) -> Result<String, VaultError>;

    /// Set up the transit secrets engine.
    async fn setup_transit_engine(&self, token: &str) -> Result<(), VaultError>;

    /// Create a transit key for encryption/decryption operations.
    async fn create_transit_key(&self, token: &str, key_name: &str) -> Result<(), VaultError>;

    /// Create a policy for transit-based auto-unseal.
    async fn create_transit_unseal_policy(
        &self,
        token: &str,
        policy_name: &str,
        key_name: &str,
    ) -> Result<(), VaultError>;

    /// Generate a token with transit auto-unseal permissions.
    async fn generate_transit_unseal_token(
        &self,
        token: &str,
        policy_name: &str,
    ) -> Result<String, VaultError>;

    /// Generate a wrapped token with transit auto-unseal permissions.
    async fn generate_wrapped_transit_unseal_token(
        &self,
        token: &str,
        policy_name: &str,
        ttl: u32,
    ) -> Result<String, VaultError>;

    /// Unwrap a token that was wrapped using Vault's response wrapping.
    async fn unwrap_token(&self, wrapped_token: &str) -> Result<String, VaultError>;
}
