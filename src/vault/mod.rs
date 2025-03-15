//! Vault client library for managing and interacting with HashiCorp Vault.

pub mod auth;
pub mod autounseal;
pub mod client;
pub mod common;
pub mod init;
pub mod operations;
pub mod pki;
pub mod status;
pub mod transit;

// Re-export key types and traits for convenience
pub use client::VaultClient;
pub use init::InitResult;
pub use operations::VaultOperations;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for Vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    /// API error returned by Vault.
    #[error("API error: {0}")]
    Api(String),

    /// API error returned by Vault with specific message.
    #[error("API error: {0}")]
    ApiError(String),

    /// Network error during communication with Vault.
    #[error("Network error: {0}")]
    Network(String),

    /// Connection error when connecting to Vault.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Error when parsing response from Vault.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Error parsing response data.
    #[error("Parsing error: {0}")]
    Parsing(String),

    /// Error constructing request to Vault.
    #[error("Request error: {0}")]
    RequestError(String),

    /// HTTP status error response.
    #[error("HTTP status {0}: {1}")]
    HttpStatus(u16, String),

    /// Vault is sealed error.
    #[error("Vault is sealed: {0}")]
    Sealed(String),

    /// Vault is already initialized.
    #[error("Vault is already initialized")]
    AlreadyInitialized,

    /// Error from the reqwest crate.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Error serializing or deserializing JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Credentials for AppRole authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleCredentials {
    /// The role_id for AppRole authentication.
    pub role_id: String,
    /// The secret_id for AppRole authentication.
    pub secret_id: String,
}
