# Merka Vault

[![Crates.io](https://img.shields.io/crates/v/merka-vault.svg)](https://crates.io/crates/merka-vault)
[![Docs.rs](https://docs.rs/merka-vault/badge.svg)](https://docs.rs/merka-vault)
[![Build](https://img.shields.io/github/actions/workflow/status/cosmicrocks/merka-vault/ci.yml?branch=main)](https://github.com/cosmicrocks/merka-vault/actions)
[![License: MIT or Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

Merka Vault is a tool that simplifies the management of HashiCorp Vault, focusing on automating vault initialization, unsealing, and setting up PKI infrastructure. It provides both a CLI interface and a programmatic API.

## Features

- Initialize and unseal Vault instances with optional recovery keys
- Configure Transit-based auto-unsealing between Vault instances
- Set up PKI secrets engine with hierarchical CA support
- Interactive setup wizard for guided configuration
- Web server with REST API and Socket.IO events for real-time monitoring
- SQLite database integration for credential storage and vault relationships
- Actor-based architecture for thread-safe operations
- Comprehensive error handling and validation

## CLI Usage

```bash
# Initialize and unseal a Vault
merka-vault init --shares=5 --threshold=3
merka-vault unseal --key="abcd1234..."

# Setup PKI infrastructure
merka-vault pki setup --domain="example.com" --ttl="8760h"

# Setup Transit-based auto-unsealing
merka-vault setup-transit --token="hvs.duSRviFEGvn..."
merka-vault generate-transit-token
merka-vault auto-unseal --transit-mount="transit" --key-name="auto-unseal"

# Use the setup wizard
merka-vault wizard

# Start the web server
merka-vault server --listen-addr="127.0.0.1:8080" --vault-addr="http://127.0.0.1:8200" --db-path="merka_vault.db"
```

## Programmatic Usage

```rust
use merka_vault::actor::{InitVault, UnsealVault, SetupPki, VaultActor};
use merka_vault::database::DatabaseManager;
use tokio::sync::broadcast;

// Initialize database
let db_manager = DatabaseManager::new("merka_vault.db").unwrap();

// Create actor with database for thread-safe operations
let (tx, rx) = broadcast::channel(100);
let actor = VaultActor::new("http://127.0.0.1:8200", Some(tx))
    .with_database(db_manager);
let actor_addr = actor.start();

// Initialize the vault
let init_result = actor_addr.send(InitVault {
    secret_shares: 1,
    secret_threshold: 1,
}).await??;

// Unseal the vault
let unseal_result = actor_addr.send(UnsealVault {
    keys: init_result.keys,
}).await??;

// Setup PKI
let pki_result = actor_addr.send(SetupPki {
    role_name: "example-com".to_string(),
}).await??;
```

## Web Server Integration

The project includes a complete web server implementation with REST API and WebSocket events, backed by SQLite storage.

```bash
# Start the vaults
docker compose up -d

# Run the web server
cargo run -- server

# Or run the example directly
cargo run --example web_server

# Run the test client
cargo run --example test_client -- --restart-sub-vault
```

The web server includes:

- **REST API** for all vault operations
- **Socket.IO** for real-time event notifications
- **SQLite storage** for credentials and vault relationships
- **Actix Actor** system for concurrent operations

For more details, see the [Examples Documentation](./docs/examples.md).

## Vault Initialization and Unsealing Process

The correct sequence for vault setup is:

1. Initialize root vault (creates unseal keys and root token)
2. Unseal the root vault (provide enough unseal keys to reach threshold)
3. Setup transit engine (requires unsealed vault)
4. Generate transit token (with permissions for auto-unsealing)
5. Restart sub vault with transit token as `VAULT_TOKEN`
6. Initialize sub vault with auto-unseal configuration
7. Setup PKI in sub vault

For a comprehensive overview of the operations, see the [Operations Documentation](./docs/operations_overview.md).

## Development

```bash
# Install dependencies
cargo build

# Run tests
cargo test

# Run module-specific tests
cargo test -p merka-vault --lib -- vault::pki::tests
cargo test -p merka-vault --lib -- vault::transit::tests
cargo test -p merka-vault --lib -- vault::auth::tests

# Run integration tests
cargo test -p merka-vault --test

# Run with logging
RUST_LOG=debug cargo run -- init

# Build release version
cargo build --release
```

## Recent Changes

- **Improved Testing**: Migrated integration tests to module-specific tests for better organization and maintainability
- **Test Utilities**: Enhanced test_utils.rs to support container-based testing for all modules
- **SQLite Integration**: Replaced file-based credential storage with a robust SQLite database
- **Web Server Improvements**: Enhanced Socket.IO implementation with proper local task handling
- **CLI Commands**: Added new `server` command for starting the web server
- **Database Schema**: Added support for storing vault relationships

## Documentation

Detailed documentation is available in the `/docs` directory:

- [Auto-Unseal Documentation](./docs/auto_unseal.md)
- [PKI Documentation](./docs/pki.md)
- [Operations Overview](./docs/operations_overview.md)
- [Examples Documentation](./docs/examples.md)
- [SQLite Database Integration](./docs/database.md)
- [Testing Guide](./docs/testing.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms.
