# Vault Auto-Unseal Using Transit Engine

## Overview

Auto-unseal is a feature in HashiCorp Vault that allows automatic unsealing of Vault nodes on startup,
eliminating the need for manual operator intervention. This document describes how to set up auto-unseal
using Vault's Transit secrets engine, where one Vault server (the "unsealer") is used to unseal another Vault server (the "target").

## Why Use Auto-Unseal?

- **Operational Efficiency**: Automates the unseal process, reducing manual operator intervention
- **Disaster Recovery**: Allows for automatic recovery after server restarts
- **High Availability**: Supports highly available Vault clusters with minimal downtime
- **Reduced Human Access**: Limits direct operator access to unseal keys

## Architecture

![Auto-Unseal Architecture](./images/auto_unseal_architecture.png)

The auto-unseal process using the Transit engine follows this workflow:

1. A primary Vault server acts as the "unsealer" with Transit engine enabled
2. Secondary Vault servers are configured to use the unsealer's Transit engine
3. The unsealer encrypts/decrypts the secondary Vault's master key components
4. When secondary Vault servers restart, they request unsealing from the primary

## Components

- **Unsealer Vault**: A Vault server that provides the Transit engine service
- **Target Vault**: A Vault server that will be auto-unsealed
- **Transit Key**: Encryption key in the Transit engine used for sealing/unsealing
- **Recovery Keys**: Special keys used to recover the target Vault if the unsealer is unavailable

## Critical Implementation Details

### Initialization and Unsealing Sequence

The proper sequence for setting up auto-unseal is crucial:

1. **Initialize Root Vault**: Create unseal keys and root token
2. **Unseal Root Vault**: Provide enough unseal keys to reach the threshold
   - **Important**: The vault MUST be unsealed before you can set up the transit engine
3. **Setup Transit Engine**: Configure the transit encryption engine (requires unsealed vault)
4. **Generate Transit Token**: Create a token with permissions for auto-unsealing
5. **Restart Sub Vault**: Run with the transit token as `VAULT_TOKEN`
6. **Initialize Sub Vault**: With auto-unseal configuration enabled
   - Note: When using transit auto-unseal, use the `AutoUnseal` method instead of `InitVault`
   - The parameters `secret_shares` and `secret_threshold` are not applicable to transit seal type
7. **Setup PKI**: Configure the PKI infrastructure in the sub vault

Failing to follow this sequence often leads to errors like "Vault is sealed" when attempting to set up the transit engine.

## Auto-Unseal Flow

1. **Setup Phase**:

   - Configure a Vault server with Transit secrets engine
   - Create a dedicated encryption key in the Transit engine
   - Generate a limited-permission token for the target Vault to use
   - Configure the target Vault to use Transit auto-unseal

2. **Initialization Phase**:

   - Initialize the target Vault with recovery keys instead of unseal keys
   - The master key is encrypted by the Transit engine and stored
   - Recovery keys are generated and should be securely stored

3. **Unsealing Phase**:
   - When the target Vault starts, it connects to the unsealer Vault
   - It sends the encrypted master key portion for decryption
   - The unsealer Vault decrypts it using the Transit key
   - The target Vault reconstructs its master key and unseals automatically

## Implementation in `merka-vault`

The auto-unseal functionality in `merka-vault` is implemented through these modules:

### `vault::autounseal` Module

This module contains the core functions for auto-unseal:

- `setup_transit_autounseal`: Sets up the Transit engine and creates an encryption key
- `configure_vault_for_autounseal`: Configures a target Vault to use Transit auto-unseal
- `init_with_autounseal`: Initializes a Vault with auto-unseal settings

### `actor` Module

The actor-based API provides a thread-safe interface for auto-unseal operations:

- `SetupTransit`: Message to set up the transit engine with a specific key name
- `AutoUnseal`: Message to initialize a vault with auto-unseal configuration
- `GetUnwrappedTransitToken`: Message to retrieve a transit token for auto-unsealing

### Setup Process

#### 1. Prepare the Unsealer Vault

```rust
// Initialize and unseal the vault first
let init_result = actor.send(InitVault {
    secret_shares: 1,
    secret_threshold: 1,
}).await??;

// Unseal the vault with the keys
actor.send(UnsealVault {
    keys: init_result.keys,
}).await??;

// Now set up the transit engine (REQUIRES the vault to be unsealed)
actor.send(SetupTransit {
    token: init_result.root_token.clone(),
    key_name: "autounseal-key",
}).await??;
```

This performs:

- Enabling the Transit secrets engine if not already enabled
- Creating an encryption key specifically for auto-unsealing
- Configuring the key to be exportable and allow deletion if needed
- Creating a policy with minimal permissions for auto-unsealing

#### 2. Generate a Transit Token

```rust
// Generate an unwrapped transit token
let unwrapped_token = actor.send(GetUnwrappedTransitToken {
    root_addr: "http://unsealer-vault:8200".to_string(),
    root_token: init_result.root_token.clone(),
    key_name: "autounseal-key".to_string(),
}).await??;

// The sub vault must be restarted with this token as VAULT_TOKEN
// VAULT_TOKEN=<unwrapped_token> docker-compose up -d sub-vault
```

#### 3. Initialize with Auto-Unseal

```rust
// Point the actor at the sub vault
actor.send(SetCurrentAddress("http://target-vault:8200".to_string())).await??;

// Initialize the target Vault with auto-unseal
let auto_unseal_result = actor.send(AutoUnseal {}).await??;

// Store the recovery keys securely
let recovery_keys = auto_unseal_result.recovery_keys.unwrap_or_default();
let sub_token = auto_unseal_result.root_token;
```

This initializes the Vault with:

- Recovery keys instead of unseal keys
- Default recovery configuration (5 shares, 3 threshold)
- Master key encryption handled by the Transit engine

### Web Server Implementation

The web server example in `examples/web_server.rs` demonstrates a complete auto-unseal setup:

```rust
// 1. Set up root vault (initialize, unseal, configure transit)
async fn setup_root_vault(state: web::Data<AppState>, req: web::Json<SetupRootRequest>) -> impl Responder {
    // Initialize the vault if not already initialized

    // CRITICAL: Unseal the vault before setting up transit

    // Set up transit engine with the key name
}

// 2. Set up sub vault with auto-unseal
async fn setup_sub_vault(state: web::Data<AppState>, req: web::Json<SetupSubRequest>) -> impl Responder {
    // Initialize sub-vault with auto unseal
    let auto_unseal_result = state.actor.send(AutoUnseal {}).await;

    // Set up PKI using the sub vault token
}
```

### Security Considerations

1. **Token Permissions**: The token used by the target Vault should have minimal permissions:

   - Only access to encrypt/decrypt operations on the specific Transit key
   - No other permissions in the unsealer Vault

2. **Recovery Keys**: Store recovery keys securely in case:

   - The unsealer Vault becomes unavailable
   - You need to migrate to a different unsealing mechanism
   - You need to perform a manual recovery

3. **Network Security**: Ensure secure communication between Vaults:
   - Use TLS for all communications
   - Implement network-level access controls between Vaults
   - Consider running both Vaults in the same network segment

## Using Auto-Unseal with CLI

The `merka-vault` CLI supports auto-unseal operations:

```bash
# Set up Transit engine on unsealer Vault
merka-vault --vault-addr="http://unsealer-vault:8200" transit setup --token="root_token"

# Create the auto-unseal key
merka-vault --vault-addr="http://unsealer-vault:8200" transit create-key --key-name="auto-unseal-key" --token="root_token"

# Create a policy for auto-unseal
merka-vault --vault-addr="http://unsealer-vault:8200" transit create-policy --policy-name="auto-unseal" --key-name="auto-unseal-key" --token="root_token"

# Generate token with the policy
merka-vault --vault-addr="http://unsealer-vault:8200" transit generate-token --policy-name="auto-unseal" --token="root_token"

# Configure and initialize target Vault (requires manual configuration)
```

## Troubleshooting

### Common Issues

1. **"Vault is sealed" Error**:

   - This usually means you're trying to set up the transit engine before unsealing the vault
   - Ensure you unseal the root vault BEFORE attempting to set up transit

2. **Connection Problems**:

   - Ensure both Vaults can communicate over the network
   - Check for TLS certificate issues if using HTTPS

3. **Permission Denied**:

   - Verify the token has sufficient permissions on the Transit key
   - Check if the Transit engine is enabled and accessible

4. **Initialization Failures**:
   - For transit auto-unseal, use `AutoUnseal` instead of `InitVault`
   - Parameters like `secret_shares` and `secret_threshold` are not applicable to transit seal
   - Ensure the unsealer Vault is available during initialization

### Logs to Check

- Look for errors related to "seal" or "unseal" in the target Vault logs
- Check for Transit engine access errors in the unsealer Vault logs
- Verify connectivity between the Vaults if you see timeout errors

## When Not to Use Auto-Unseal

Auto-unseal may not be appropriate in all scenarios:

- **Single Vault Deployment**: Using auto-unseal creates a circular dependency if only one Vault exists
- **Highest Security Requirements**: For extremely sensitive environments where any automation introduces risk
- **Simple Development Environments**: May be unnecessary overhead for local development

## References

- [HashiCorp Vault Auto-Unseal Documentation](https://www.vaultproject.io/docs/concepts/seal#auto-unseal)
- [Transit Secrets Engine](https://www.vaultproject.io/docs/secrets/transit)
- [Auto-Unseal with Transit Keys](https://learn.hashicorp.com/tutorials/vault/autounseal-transit)
