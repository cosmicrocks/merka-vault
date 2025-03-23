//! Vault client library for managing and interacting with HashiCorp Vault.

pub mod auth;
pub mod autounseal;
pub mod client;
pub mod common;
pub mod error;
pub mod init;
pub mod operations;
pub mod pki;
pub mod setup_root;
pub mod setup_sub;
pub mod status;
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
