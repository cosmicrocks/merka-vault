//! Vault module for the Merka Vault library
//!
//! This module implements the core functionality for interacting with HashiCorp Vault.
//! It provides low-level operations that should be coordinated through the actor module.
//!
//! ## Architectural role:
//! - Implements core vault operations (initialization, unseal, etc.)
//! - Should be accessed through the actor module by the server
//! - May be accessed directly by the CLI module
//! - Is not exposed directly to external users of the library (pub(crate))
//!
//! ## Testing strategy:
//! - Each module contains its own unit tests within a `#[cfg(test)] mod tests` block
//! - Tests use Docker containers via the `test_utils.rs` module when needed
//! - Tests validate both success paths and error handling scenarios
//! - The `test_utils.rs` module provides helper functions for setting up test environments
//! - Integration tests in the `tests/` directory test cross-module functionality

pub mod auth;
pub mod autounseal;
pub mod client;
pub mod common;
pub mod error;
pub mod init;
pub mod operations;
pub mod pki;
pub mod seal;
pub mod setup_root;
pub mod setup_sub;
pub mod status;
#[cfg(test)]
pub mod test_utils;
pub mod transit;
pub mod wizard;

// Re-export key types and traits for convenience
pub use auth::*;
pub use client::VaultClient;
pub use common::VaultStatus;
pub use error::VaultError;
pub use init::{init_vault, unseal_root_vault, InitResult, UnsealResult};
pub use operations::VaultOperations;
pub use pki::PkiResult;
pub use seal::seal_vault;
pub use wizard::{run_setup_wizard, WizardConfig, WizardResult};

use serde::{Deserialize, Serialize};

/// Credentials for AppRole authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleCredentials {
    /// The role_id for AppRole authentication.
    pub role_id: String,
    /// The secret_id for AppRole authentication.
    pub secret_id: String,
}

/// Result type for auto-unseal operations
#[derive(Debug, Clone)]
pub struct AutoUnsealResult {
    pub root_token: String,
    pub recovery_keys: Option<Vec<String>>,
    pub success: bool,
}

/// Vault configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultConfig {
    /// Vault API URL, e.g., "http://127.0.0.1:8200".
    pub url: String,
    /// Optional API token. Some operations (e.g., status) don't require a token,
    /// but most do.
    pub token: Option<String>,
    /// Optional client certificate for mTLS connections
    pub client_cert_path: Option<String>,
    /// Optional client key for mTLS connections
    pub client_key_path: Option<String>,
    /// Optional CA certificate for verifying the server
    pub ca_cert_path: Option<String>,
    /// Optional namespace for supporting namespaced Vault instances (enterprise)
    pub namespace: Option<String>,
}

impl VaultConfig {
    /// Create a new Vault config
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            token: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
            namespace: None,
        }
    }

    /// Set token
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    /// Set mTLS cert paths
    pub fn with_mtls(mut self, client_cert: &str, client_key: &str, ca_cert: Option<&str>) -> Self {
        self.client_cert_path = Some(client_cert.to_string());
        self.client_key_path = Some(client_key.to_string());
        self.ca_cert_path = ca_cert.map(|s| s.to_string());
        self
    }

    /// Set namespace
    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }
}

// Default configuration
impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8200".to_string(),
            token: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
            namespace: None,
        }
    }
}
