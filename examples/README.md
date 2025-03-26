# Merka Vault Examples

This directory contains examples to demonstrate how to use the Merka Vault library in real-world scenarios.

## Key Concepts in Vault Architecture

The Merka Vault system is designed with a hierarchical relationship between vaults:

1. **Root Vault** - Provides transit encryption service for auto-unsealing
2. **Sub Vault** - Uses the root vault's transit engine to automatically unseal itself
3. **Auto-unseal Process** - Requires a transit token with proper permissions

## Vault Initialization and Unsealing Process

The setup process follows these critical steps:

1. **Initialize the Root Vault** - This creates unseal keys and a root token
2. **Unseal the Root Vault** - The vault must be unsealed with the generated keys
3. **Setup Transit Engine** - Only possible once the vault is unsealed
4. **Generate Transit Token** - For the sub vault to use
5. **Restart Sub Vault** - With the transit token as VAULT_TOKEN
6. **Initialize Sub Vault** - With auto-unseal configured

**Important**: The vault MUST be unsealed after initialization before you can set up the transit engine.

## Web Server Example

The web server example (`web_server.rs`) demonstrates how to:

1. Start a web server with a REST API for Vault operations
2. Use the Vault Actor to interact with Vault instances
3. Stream events from the Vault Actor to clients via Socket.IO
4. Monitor multiple Vault instances and track relationships

### Running the Web Server Example

Prerequisites:

- Docker and Docker Compose installed
- Rust toolchain

Steps:

1. Start the Vault instances using Docker Compose from the project root:

   ```
   docker-compose up -d
   ```

2. Run the web server example:

   ```
   cargo run --example web_server
   ```

3. The server will be available at http://localhost:8080 with API endpoints at `/api/...`

### API Endpoints

The web server provides a direct mapping to CLI commands:

- `GET /api/list` - List all known vaults and their status
- `POST /api/unseal` - Unseal a Vault
- `GET /api/status` - Check Vault status
- `POST /api/setup` - Setup wizard (placeholder for non-interactive setup)
- `POST /api/setup_root` - Set up the root Vault for auto-unseal
- `POST /api/setup_sub` - Set up the sub Vault with auto-unseal and PKI
- `POST /api/get_transit_token` - Get an unwrapped transit token for auto-unseal

### Socket.IO Integration

The web server uses Socket.IO to push real-time events to connected clients. Events include:

- `initialized` - Vault has been initialized
- `unsealed` - Vault has been unsealed
- `pki_setup_complete` - PKI setup completed
- `autounseal_complete` - Auto-unseal process completed
- `status_checked` - Status check performed
- `vault_health_updated` - Health status updated
- `error` - Error occurred

### Implementation Notes

- Uses `socketioxide` v0.16.2 for Socket.IO server implementation
- Creates a broadcast channel to distribute Vault events to all connected clients
- Maintains a connection map to track active Socket.IO connections
- Sends serialized JSON events to connected clients
- Gracefully handles disconnections

## Test Client Example

The test client example (`test_client.rs`) demonstrates how to:

1. Connect to the web server REST API
2. Set up a complete vault environment with auto-unseal
3. Handle the crucial step of restarting the sub vault with the transit token

### Important: The VAULT_TOKEN Environment Variable

The most critical part of the auto-unseal process is properly setting the VAULT_TOKEN environment variable when starting the sub vault. This token allows the sub vault to authenticate with the root vault's transit engine for auto-unsealing.

```bash
VAULT_TOKEN=<transit_token> docker-compose up -d sub-vault
```

**Without this token, the sub vault container will start with an empty token and auto-unseal will fail.**

### Running the Test Client Example

Prerequisites:

- Web server example is running
- Vault instances are running via Docker Compose

Steps:

1. Run the test client example:

   ```
   # Basic setup - prints instructions for manual restart
   cargo run --example test_client

   # Automatically restarts sub vault with transit token
   cargo run --example test_client -- --restart-sub-vault
   ```

2. Watch the logs to see the events being received from the web server.

### Expected Flow

1. Root vault is initialized and unsealed
2. Transit engine is enabled and a policy for auto-unseal is created
3. A transit token is generated for the sub vault to use
4. Sub vault is restarted with the transit token as VAULT_TOKEN
5. Sub vault initializes with auto-unseal configuration
6. Sub vault is automatically unsealed using the root vault's transit engine

## Troubleshooting

### "Vault is sealed" Error

If you see errors like "Failed to setup transit engine: Vault is sealed", it means:

1. The vault instance is running and may have been initialized but is still sealed
2. You need to ensure that after initialization, the vault is unsealed before setting up the transit engine
3. The test_client has been updated to explicitly unseal the vault after initialization

### Initialization and Unsealing Flow

The proper sequence is critical:

1. Initialize vault → Get unseal keys and root token
2. Unseal vault with the keys
3. Then set up transit engine with root token
4. Generate transit token
5. Restart sub vault with token

If any step is missed or done out of order, you'll encounter errors.

### VAULT_TOKEN Issues

If auto-unseal is not working for the sub vault:

1. Check that the sub vault was restarted with the proper VAULT_TOKEN
2. Verify the token format is correct (not truncated or modified)
3. Run `docker logs merka-vault-sub` to check for auth-related errors

Remember that the VAULT_TOKEN must be correctly set when starting the sub vault container:

```bash
VAULT_TOKEN=<transit_token> docker-compose up -d sub-vault
```

### Web Server Connection Issues

If the test client cannot connect to the web server:

1. Ensure the web server is running with `cargo run --example web_server`
2. Check the web server logs for any startup errors
3. Verify that port 8080 is not in use by another application

## Integration Testing

The examples can also be used for integration testing:

1. `tests/example_test.rs` - Integration test for the web server and test client
2. `tests/test_integration.rs` - Comprehensive tests that mirror the functionality of the examples

### Example Test

The `example_test.rs` file demonstrates how to use the web server and test client together as an integration test. It automatically sets up and manages the required Docker Compose environment.

To run the integration test:

```bash
cargo test --test example_test
```

This test runs in serial mode to avoid port conflicts with other Docker Compose tests.

### Database-Backed Integration Tests

The `test_integration.rs` file contains more comprehensive tests:

- `test_database_operations` - Tests SQLite database operations
- `test_vault_setup_flow` - Tests the complete vault setup flow

These tests are designed to validate the functionality demonstrated in the examples but in a proper testing framework.

To run these tests:

```bash
# Start the web server first
cargo run -- server

# Run the vault setup flow test
cargo test -p merka-vault test_vault_setup_flow -- --nocapture
```

For more details on testing, see the [Testing Guide](../docs/testing.md).
