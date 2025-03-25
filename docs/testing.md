# Merka Vault Testing Guide

This document provides an overview of the testing approach for the Merka Vault project, including unit tests, integration tests, and end-to-end testing with Docker Compose.

## Testing Approach

The Merka Vault project follows a comprehensive testing strategy:

1. **Module-Specific Tests**: Testing individual components in isolation

   - Located directly in the module being tested (e.g., `src/vault/pki.rs` contains PKI tests)
   - Use test containers when needed via `test_utils.rs`
   - Do not require external dependencies to run

2. **Integration Tests**: Testing interactions between components

   - Located in the `tests/` directory
   - Test the public API and cross-module interactions
   - May require Docker containers or external services

3. **End-to-End Tests**: Testing complete workflows with actual Vault instances
   - Located in the `tests/` directory
   - Use Docker Compose to set up the complete environment
   - Test real-world scenarios and workflows

## Module-Specific Testing

Each module in the `src/vault/` directory includes its own tests that validate the functionality of that module. This approach has several advantages:

1. **Proximity to Code**: Tests live alongside the code they are testing
2. **Clear Ownership**: Module maintainers are responsible for their tests
3. **Focused Tests**: Each test focuses on specific functionality
4. **Easier Maintenance**: Tests are updated when the module changes

### Example of Module Tests

```rust
// Inside src/vault/transit.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;
    use crate::vault::test_utils::{setup_vault_container, wait_for_vault_ready, VaultMode};

    #[tokio::test]
    async fn test_transit_setup() -> Result<(), Box<dyn std::error::Error>> {
        // Test code here
    }
}
```

### Test Utilities

The project includes a comprehensive test utilities module (`src/vault/test_utils.rs`) that provides:

1. Functions for setting up Docker containers
2. Wait functions to ensure services are ready
3. Helper functions for common test operations
4. Support for different Vault modes (Dev, Regular, AutoUnseal)

This allows unit tests to:

- Create ephemeral test containers when needed
- Test error handling when services are unavailable
- Validate functionality against real Vault instances

## Actor-Based Testing Approach

To maintain architectural boundaries while allowing comprehensive testing, we also use the actor-based approach for integration tests. This approach has several advantages:

1. Tests the code the way users would actually use it
2. Enforces architectural boundaries naturally
3. Avoids leaking implementation details
4. Results in more robust tests that won't break with internal refactoring

### Actor Utility Module

The project includes a set of actor utility functions in `tests/common/actor_utils.rs` that simplify working with the `VaultActor`:

```rust
// Create an actor with event channel and optional database
let (actor, mut rx) = actor_utils::create_actor("http://127.0.0.1:8200", None);

// Initialize the vault
let (root_token, keys) = actor_utils::initialize_vault(&actor, 1, 1).await?;

// Unseal the vault
let status = actor_utils::unseal_vault(&actor, keys).await?;

// Set up a root vault
let token = actor_utils::setup_root_vault(&actor, url, 1, 1, "key-name").await?;
```

### Example Tests

For examples of the actor-based approach, see the tests in `tests/test_actor.rs`. These examples demonstrate:

1. Basic vault operations (initialization, unsealing, status checks)
2. Working with the event system
3. Setting up a root vault for auto-unseal
4. Waiting for specific events

## Architecture and Testing

The Merka Vault library follows a strict architectural separation of concerns:

- The `server` module can only access the `actor` module for all vault operations
- The `actor` module can access both the `vault` and `database` modules
- The `cli` module can access both the `actor` and `vault` modules
- The `vault` module is private (`pub(crate)`) and not exposed to external users

All tests are designed to respect these architectural boundaries:

1. **Module Unit Tests**: Test only the functionality of their specific module
2. **Actor-Based Tests**: Test the actor interface to ensure architectural boundaries
3. **Integration Tests**: Test cross-module interactions through the public API

## Test Directory Structure

- `src/vault/*/tests.rs`: Module-specific unit tests
- `tests/`: Contains integration and end-to-end tests
  - `common/`: Shared test utilities and fixtures
  - `test_actor.rs`: Tests for the actor-based API
  - `test_integration.rs`: End-to-end tests with the web server and database
  - `test_vault_setup.rs`: Tests for vault setup workflows
  - `example_test.rs`: Tests for the example applications

## Running Tests

### Running Tests Manually

```bash
# Run all tests
cargo test -p merka-vault

# Run module-specific tests
cargo test -p merka-vault --lib -- vault::pki::tests
cargo test -p merka-vault --lib -- vault::transit::tests::test_transit_setup

# Run actor-based tests
cargo test -p merka-vault --test test_actor

# Run with detailed output
cargo test -p merka-vault -- --nocapture
```

## Integration Tests with Docker

Many tests require running Vault instances. The project uses Docker containers for this purpose:

```bash
# Start the Docker Compose environment for testing
docker-compose up -d

# Run integration tests that require Docker
cargo test -p merka-vault test_vault_setup_flow -- --nocapture
```

## Database-Backed Integration Tests

The `test_integration.rs` file contains tests that use SQLite for persistent storage:

### Database Operations Test

The `test_database_operations` test validates core database functionality:

- Creating and initializing a test database
- Saving and loading vault credentials
- Managing unsealer relationships
- Cleaning up resources after testing

```bash
cargo test -p merka-vault test_database_operations -- --nocapture
```

### Vault Setup Flow Test

The `test_vault_setup_flow` test mirrors the functionality in `examples/test_client.rs` but follows proper testing patterns:

1. Checks if the web server is running (required)
2. Initializes a test database and cleans up any existing files
3. Starts the Docker Compose environment
4. Checks the initial vault status
5. Initializes the root vault if needed
6. Unseals the vault if needed
7. Gets a transit token for auto-unseal
8. Restarts the sub vault with the transit token
9. Sets up the sub vault with auto-unseal and PKI
10. Verifies the vault status and credentials
11. Cleans up resources when done

```bash
# Start the web server first
cargo run -- server

# Then run the test in another terminal
cargo test -p merka-vault test_vault_setup_flow -- --nocapture
```

## Test Prerequisites

### Web Server

Some tests require the web server to be running:

```bash
# Start the server
cargo run -- server
```

The `test_vault_setup_flow` test will automatically check if the server is running and skip the test if it's not.

### Docker Compose

```bash
# Start Docker Compose
docker-compose up -d

# Stop Docker Compose when done
docker-compose down
```

## Writing New Tests

When adding new functionality to the codebase, follow these guidelines for testing:

1. **Module-Specific Tests**: Add unit tests directly in the module you're modifying
2. **Actor Interface**: Test public functionality through the actor interface
3. **Error Handling**: Include tests for both success and failure cases
4. **Container Tests**: Use the test_utils module for container-based testing

### Example: Adding a New Feature

When adding a new feature to a module:

1. Implement the feature in the appropriate module
2. Add unit tests in the module's `#[cfg(test)] mod tests` block
3. If needed, add actor-based integration tests in `tests/test_actor.rs`
4. Update documentation to reflect the new feature and its testing

This approach ensures comprehensive test coverage while maintaining the project's architectural boundaries.

## Common Test Issues

### Server Not Running

If you see "Web server not running" in the test output, start the server with:

```bash
cargo run -- server
```

### Docker Not Running

If tests fail with Docker-related errors, ensure Docker is running and containers can be started:

```bash
docker ps
docker-compose up -d
```

### Database Errors

If you see database errors, ensure the test has proper permissions to create and write to database files. You might need to manually clean up stale database files:

```bash
rm *.db
```

### Vault Already Initialized

The tests are designed to handle Vault instances that are already initialized, but if you encounter issues, you can reset the Docker environment:

```bash
docker-compose down -v
docker-compose up -d
```

## Test Coverage

The current test suite covers:

- Database operations
- Vault initialization and unsealing
- Transit auto-unseal setup
- PKI infrastructure setup
- Web server API interaction
- Credential management

Areas for future test expansion:

- Error handling and recovery scenarios
- Performance testing
- More comprehensive API endpoint testing
- Security testing

## References

- [Rust Testing Documentation](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [tokio Testing Guide](https://tokio.rs/tokio/tutorial/testing)
- [HashiCorp Vault Testing](https://developer.hashicorp.com/vault/tutorials/operations/testing-vault)
- [Actix Testing](https://actix.rs/docs/testing/)
