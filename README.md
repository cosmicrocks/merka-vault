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
- Web server example with REST API and Socket.IO events
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
```

## Programmatic Usage

```rust
use merka_vault::actor::{InitVault, UnsealVault, SetupPki, start_vault_actor};

// Create an actor for thread-safe operations
let actor = start_vault_actor("http://127.0.0.1:8200");

// Initialize the vault
let init_result = actor.send(InitVault {
    secret_shares: 1,
    secret_threshold: 1,
}).await??;

// Unseal the vault
let unseal_result = actor.send(UnsealVault {
    keys: init_result.keys,
}).await??;

// Setup PKI
let pki_result = actor.send(SetupPki {
    role_name: "example-com".to_string(),
}).await??;
```

## Web Server Example

The project includes a complete web server implementation with REST API and WebSocket events.

```bash
# Start the vaults
docker compose up -d

# Run the web server
cargo run --example web_server

# Run the test client
cargo run --example test_client -- --restart-sub-vault
```

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

# Run with logging
RUST_LOG=debug cargo run -- init

# Build release version
cargo build --release
```

## Documentation

Detailed documentation is available in the `/docs` directory:

- [Auto-Unseal Documentation](./docs/auto_unseal.md)
- [PKI Documentation](./docs/pki.md)
- [Operations Overview](./docs/operations_overview.md)
- [Examples Documentation](./docs/examples.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms.
