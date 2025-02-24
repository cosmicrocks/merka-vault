//! The `vault` module provides functions to initialize, configure PKI, and set up auth for HashiCorp Vault.
//! It re-exports submodules for initialization, PKI, and auth functionality.

pub mod auth;
pub mod init;
pub mod operations;
pub mod pki;

mod common; // Private helper functions.

use reqwest::StatusCode;
use thiserror::Error;

/// Errors returned by Vault operations.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Vault API error: {0}")]
    Api(String),
    #[error("Vault returned HTTP status: {0}")]
    HttpStatus(StatusCode),
}

/// Result type for Vault initialization.
pub struct InitResult {
    pub root_token: String,
    pub keys: Vec<String>,
}

/// Credentials returned from AppRole setup.
pub struct AppRoleCredentials {
    pub role_id: String,
    pub secret_id: String,
}
