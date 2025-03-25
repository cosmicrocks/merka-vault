# Merka Vault Tests

This directory contains integration tests for the Merka Vault library. These tests verify the functionality of various components working together, including:

- Vault initialization and unsealing
- Transit-based auto-unsealing
- PKI infrastructure setup
- Actor-based API
- Database operations

## Preferred Testing Approach: Module-Specific and Actor-Based Testing

The recommended approach for testing the Merka Vault library is:

1. **Module-Specific Tests**: Each module contains its own tests in a `#[cfg(test)] mod tests` block
2. **Actor-Based Tests**: For cross-module functionality, use the actor-based API

### Module-Specific Testing

Module-specific tests are located directly in the source files they are testing:

```rust
// Inside src/vault/transit.rs, src/vault/pki.rs, etc.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_logging;
    use crate::vault::test_utils::{setup_vault_container, wait_for_vault_ready, VaultMode};

    #[tokio::test]
    async fn test_functionality() -> Result<(), Box<dyn std::error::Error>> {
        // Test code here
    }
}
```

These tests validate the functionality of specific modules in isolation, ensuring that each component works correctly.

### Actor Utility Module

For integration testing, the `common/actor_utils.rs` module provides utilities for working with the `VaultActor`:

```rust
// Create an actor with an event channel
let (actor, mut rx) = actor_utils::create_actor("http://127.0.0.1:8200", None);

// Initialize and unseal a vault
let (token, keys) = actor_utils::initialize_vault(&actor, 1, 1).await?;
let status = actor_utils::unseal_vault(&actor, keys).await?;

// Set up a root vault with transit for auto-unseal
let transit_token = actor_utils::setup_root_vault(&actor, url, 1, 1, "key-name").await?;
```

### Example Tests

For concrete examples of the actor-based approach, see the tests in `test_actor.rs`. These show how to:

1. Initialize and unseal a vault using the actor
2. Monitor events from vault operations
3. Set up transit-based auto-unsealing
4. Wait for specific events with timeouts

## Architecture and Testing

The Merka Vault library has a strict architectural separation:

- The `server` module can only access the `actor` module
- The `actor` module can access both the `vault` and `database` modules
- The `cli` module can access both the `actor` and `vault` modules
- The `vault` module is private (`pub(crate)`) with module-specific tests

### Benefits of the New Testing Approach

1. **Proximity to Code**: Tests are located near the code they test
2. **Clear Ownership**: Each module is responsible for its own tests
3. **Focused Tests**: Each test focuses on a specific functionality
4. **Simpler Maintenance**: Tests evolve alongside the code they test

## Test Files

- `src/vault/*/tests` - Module-specific unit tests within each module
- `test_actor.rs` - Examples of the actor-based testing approach
- `test_actor_integration.rs` - Tests for the actor-based API
- `test_integration.rs` - End-to-end tests with the web server and database
- `test_vault_setup.rs` - Tests for vault setup workflows
- `example_test.rs` - Tests for example applications
- `common/mod.rs` - Shared utilities and helpers for tests
- `common/actor_utils.rs` - Actor-based testing utilities

## Test Types

### Module-Specific Tests

Located directly in the source modules:

- `vault::pki::tests::test_setup_pki` - Tests for PKI setup
- `vault::transit::tests::test_transit_setup` - Tests for transit setup
- `vault::auth::tests::test_setup_approle` - Tests for auth setup
- `vault::init::tests::test_init_and_unseal` - Tests for vault initialization
- `vault::autounseal::tests::test_autounseal_workflow` - Tests for auto-unseal

### Actor-Based Tests

These tests use the actor interface:

- `test_basic_vault_operations_using_actor` - Basic operations using actor
- `test_actor_events` - Event handling with the actor
- `test_setup_root_with_actor` - Transit setup using actor
- `test_waiting_for_events` - Event waiting utility

## Best Practices

When writing new tests:

1. **Use module-specific tests** for component-level functionality
2. **Use the actor-based approach** for integration tests
3. Keep database-only tests separate as they use the public database API

For more information, see the [Testing Guide](../docs/testing.md).
