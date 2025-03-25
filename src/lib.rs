//! merka-vault - Vault provisioning library
//!
//! This crate provides tools to initialize and configure a HashiCorp Vault server.
//! It includes an Actix actor (`VaultActor`) for use in async systems and
//! standalone functions for direct use or CLI.
//!
//! ## Architecture
//!
//! The crate follows a layered architecture with the following dependencies:
//!
//! - `server` module - HTTP API layer (can only access actor module)
//! - `actor` module - Domain layer (can access vault and database modules)
//! - `cli` module - Command-line interface (can access actor module)
//! - `vault` module - Vault implementation (core functionality, private to crate)
//! - `database` module - Persistence layer (accessed through actor module)
//!
//! This enforces separation of concerns and a clean dependency hierarchy.
//! The vault module is private to the crate, ensuring all external access
//! goes through the actor module, which enforces business rules and manages
//! persistence.

// Make modules available with appropriate visibility
pub mod actor;
pub mod cli;
pub mod database;

// Interface module is available to all other modules
pub mod interface;

// Vault module is private to the crate to enforce the architectural constraints
pub(crate) mod vault;

// Server module is public for the binary but should only use actor
pub mod server;

// Re-export public types for convenience
pub use actor::VaultActor;
pub use database::{DatabaseManager, VaultCredentials};

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
