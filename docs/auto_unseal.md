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

### Setup Process

#### 1. Prepare the Unsealer Vault

```rust
// Setup Transit engine for auto-unseal
let unsealer_vault_url = "http://unsealer-vault:8200";
let token = "root_token_of_unsealer";
let key_name = "auto-unseal-key";

// Set up the Transit engine and create encryption key
let result = merka_vault::vault::autounseal::setup_transit_autounseal(
    &unsealer_vault_url,
    token,
    key_name
).await?;
```

This performs:

- Enabling the Transit secrets engine if not already enabled
- Creating an encryption key specifically for auto-unsealing
- Configuring the key to be exportable and allow deletion if needed

#### 2. Configure the Target Vault

```rust
// Configure target Vault to use the unsealer Vault
let target_vault_url = "http://target-vault:8200";
let config_result = merka_vault::vault::autounseal::configure_vault_for_autounseal(
    &target_vault_url,
    &unsealer_vault_url,
    token,
    key_name,
).await?;
```

This configures the target Vault's configuration to:

- Set the seal type to "transit"
- Specify the unsealer Vault's address
- Configure the token to use for Transit operations
- Set the key name to use for encryption/decryption

#### 3. Initialize with Auto-Unseal

```rust
// Initialize the target Vault with auto-unseal
let init_result = merka_vault::vault::autounseal::init_with_autounseal(&target_vault_url).await?;

// Store the recovery keys securely
let recovery_keys = init_result.recovery_keys.unwrap_or_default();
let root_token = init_result.root_token;
```

This initializes the Vault with:

- Recovery keys instead of unseal keys
- Default recovery configuration (5 shares, 3 threshold)
- Master key encryption handled by the Transit engine

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

1. **Connection Problems**:

   - Ensure both Vaults can communicate over the network
   - Check for TLS certificate issues if using HTTPS

2. **Permission Denied**:

   - Verify the token has sufficient permissions on the Transit key
   - Check if the Transit engine is enabled and accessible

3. **Initialization Failures**:
   - Confirm the target Vault configuration is correct
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
