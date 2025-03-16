//! merka-vault - Vault provisioning library
//!
//! This crate provides tools to initialize and configure a HashiCorp Vault server.
//! It includes an Actix actor (`VaultActor`) for use in async systems and
//! standalone functions for direct use or CLI.

pub mod actor;
pub mod cli;
pub mod db;
pub mod interface;
pub mod vault;

pub use actor::VaultActor;

/// Initialize logging for the application
#[allow(dead_code)]
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer() // This ensures output goes to both stdout and test output
        .try_init();
}

pub trait VaultService {
    fn run_api_server(
        &self,
        root_vault_addr: &str,
        sub_vault_addr: &str,
        listen_addr: &str,
    ) -> impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send;
}
