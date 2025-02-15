// src/lib.rs
//! merka-vault - Vault provisioning library
//!
//! This crate provides tools to initialize and configure a HashiCorp Vault server.
//! It includes an Actix actor (`VaultActor`) for use in async systems and
//! standalone functions for direct use or CLI.

pub mod actor;
pub mod vault;

pub use actor::VaultActor;
pub use actor::{AppRoleCredentials, InitResult, PkiResult};
