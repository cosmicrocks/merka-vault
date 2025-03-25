# Merka Vault Operations Overview

This document provides a comprehensive overview of the core operations in the Merka Vault system, including:

1. Vault Initialization
2. Unsealing Process
3. Auto-Unseal Configuration
4. PKI Setup and Management

## Core Operation Sequence

For a proper setup of the Merka Vault system, operations must happen in the following sequence:

### 1. Root Vault Setup

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────┐
│  Initialize     │     │  Unseal with    │     │  Setup Transit      │
│  Root Vault     │────▶│  Unseal Keys    │────▶│  Engine            │
└─────────────────┘     └─────────────────┘     └─────────────────────┘
                                                          │
┌─────────────────────┐                                   │
│  Generate Transit   │◀──────────────────────────────────┘
│  Token              │
└─────────────────────┘
```

### 2. Sub Vault Setup with Auto-Unseal

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────┐
│  Restart Sub    │     │  Initialize with │     │  Setup PKI         │
│  Vault with     │────▶│  Auto-Unseal    │────▶│  Infrastructure     │
│  Transit Token  │     │  Configuration  │     │                     │
└─────────────────┘     └─────────────────┘     └─────────────────────┘
```

## Vault Initialization and Unsealing

### Initialization

The first step for a new Vault instance is initialization, which:

1. Generates the master key shares (unseal keys)
2. Creates the initial root token
3. Sets up the encryption keys for seal/unseal operations

```bash
# Using the CLI
merka-vault init --shares=5 --threshold=3

# Using the Web Server API
POST /api/init
```

### Unsealing

Unsealing is required after initialization or whenever the vault has been sealed:

1. Provide enough unseal keys to reach the threshold
2. The vault reconstructs the master key and decrypts the encryption key
3. The vault becomes available for operations

```bash
# Using the CLI
merka-vault unseal --key="nsYnIzgG+..."

# Using the Web Server API
POST /api/unseal
```

> **CRITICAL**: The vault must be unsealed before configuring transit engine or performing any other operations.

## Auto-Unseal Configuration

Auto-unseal allows a vault to unseal automatically on startup without manual intervention.

### Root Vault Setup

1. **Initialize and Unseal** the root vault first
2. **Setup Transit Engine** in the unsealed root vault:

   ```bash
   # Using the CLI
   merka-vault setup-transit

   # Using the Web Server API
   POST /api/setup_transit
   ```

3. **Generate Transit Token** with appropriate permissions:

   ```bash
   # Using the CLI
   merka-vault generate-transit-token

   # Using the Web Server API
   POST /api/generate_transit_token
   ```

### Sub Vault Configuration

1. **Restart the Sub Vault** with the transit token:

   ```bash
   # Set transit token as environment variable
   export VAULT_TOKEN="hvs.CAESILaf..."
   ```

2. **Initialize with Auto-Unseal** configuration:

   ```bash
   # Using the CLI
   merka-vault auto-unseal --transit-mount="transit" --key-name="auto-unseal"

   # Using the Web Server API
   POST /api/auto_unseal
   ```

3. **Store Recovery Keys** securely for disaster recovery scenarios

> **NOTE**: For sub vault initialization, the `AutoUnseal` message should be used instead of `InitVault` since transit auto-unseal does not use Shamir key splitting.

## PKI Infrastructure Setup

PKI setup must happen after auto-unseal is configured, using the sub vault token:

1. **Set Up PKI** with appropriate role name:

   ```bash
   # Using the CLI
   merka-vault pki setup --token="sub_token" --common-name="example.com"

   # Using the Web Server API
   POST /api/setup_sub_vault
   ```

2. **Configure Certificate Parameters**:
   - Set appropriate TTLs
   - Define allowed domains
   - Configure key usage extensions

## Web Server Example Operations

The web server example (`examples/web_server.rs`) provides a REST API for all these operations:

### Root Vault Operations

- `POST /api/setup_root` - Initialize, unseal, and set up transit engine
- `POST /api/init` - Initialize vault only
- `POST /api/unseal` - Unseal vault only
- `POST /api/setup_transit` - Set up transit engine only
- `POST /api/generate_transit_token` - Generate token for auto-unseal

### Sub Vault Operations

- `POST /api/setup_sub_vault` - Initialize with auto-unseal and set up PKI
- `POST /api/auto_unseal` - Configure auto-unseal only

## Common Issues and Troubleshooting

### Initialization Failures

- Verify that the Vault instance is running and accessible
- Check network connectivity between services
- Ensure the Vault hasn't been initialized already

### Unsealing Problems

- Ensure you're providing enough unseal keys to reach the threshold
- Verify the unseal keys are correct and properly formatted
- Check that the Vault instance is running and accessible

### Auto-Unseal Issues

- **"Vault is sealed"**: Ensure the root vault is unsealed before setting up transit
- **Connection errors**: Check network connectivity between vaults
- **Permission denied**: Verify the transit token has the correct policies

### PKI Problems

- **Authentication errors**: Make sure you're using the sub vault token, not the root token
- **Certificate chain issues**: Verify the full chain is included in responses
- **TTL limits**: Ensure requested TTLs don't exceed role or CA limits

## Best Practices

1. **Security**:

   - Store unseal keys and tokens securely
   - Use different tokens for different operations
   - Apply principle of least privilege for all tokens

2. **Operational**:

   - Follow the correct sequence of operations
   - Test the end-to-end workflow in a staging environment
   - Document and automate the setup process

3. **Recovery**:
   - Plan for disaster recovery scenarios
   - Test the recovery process regularly
   - Securely back up recovery keys

## References

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Auto-Unseal Documentation](./auto_unseal.md)
- [PKI Documentation](./pki.md)
