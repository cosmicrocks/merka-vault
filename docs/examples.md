# Merka Vault Examples

This document describes the example code provided in the Merka Vault project, focusing on the web server and test client implementations.

## Web Server Example

The web server example (`examples/web_server.rs`) demonstrates a complete implementation of a REST API and Socket.IO server for managing Vault instances with the following capabilities:

- Vault initialization and unsealing
- Transit-based auto-unseal setup
- PKI infrastructure configuration
- WebSocket events for real-time operation status

### Operation Sequence

For proper vault setup, operations should follow this sequence:

1. Initialize root vault (`/api/setup_root` or `/api/init`)
2. Unseal root vault (`/api/unseal`) if not done in step 1
3. Setup transit engine (`/api/setup_transit`) if not done in step 1
4. Generate transit token (`/api/generate_transit_token`)
5. Restart sub vault with transit token
6. Initialize sub vault with auto-unseal (`/api/setup_sub_vault` or `/api/auto_unseal`)
7. Setup PKI in sub vault (part of `/api/setup_sub_vault`)

### API Endpoints

| Endpoint                         | Method | Description                                                  |
| -------------------------------- | ------ | ------------------------------------------------------------ |
| `/api/setup_root`                | POST   | Full root vault initialization, unsealing, and transit setup |
| `/api/init`                      | POST   | Initialize a vault instance                                  |
| `/api/unseal`                    | POST   | Unseal a vault instance                                      |
| `/api/setup_transit`             | POST   | Set up the transit engine                                    |
| `/api/generate_transit_token`    | POST   | Generate a token for transit auto-unseal                     |
| `/api/setup_sub_vault`           | POST   | Set up a sub vault with auto-unseal and PKI                  |
| `/api/auto_unseal`               | POST   | Configure auto-unseal only                                   |
| `/api/status`                    | GET    | Check vault status                                           |
| `/api/health`                    | GET    | Simple health check                                          |
| `/api/list-vaults`               | GET    | List all registered vaults                                   |
| `/api/check-dependencies`        | GET    | Check auto-unseal dependencies                               |
| `/api/seal`                      | POST   | Seal a vault instance                                        |
| `/api/register-vault`            | POST   | Register a vault in the system                               |
| `/api/add-unsealer-relationship` | POST   | Add an unsealer relationship between vaults                  |
| `/api/unwrap-token`              | POST   | Unwrap a wrapped transit token                               |
| `/api/get-transit-token`         | GET    | Get an already generated transit token                       |

### Running the Web Server

```bash
cargo run --example web_server
```

The server will start on port 8080 by default. You can then interact with it using any HTTP client or WebSocket client for real-time events.

### Socket.IO Events

The web server also provides Socket.IO events for real-time monitoring:

- `vault_init` - Vault initialization event
- `vault_unseal` - Vault unsealing event
- `vault_seal` - Vault sealing event
- `transit_setup` - Transit engine setup event
- `pki_setup` - PKI setup event
- `auto_unseal` - Auto-unseal configuration event
- `dependency_check` - Dependency check event

### Vault Credentials

The web server saves vault credentials to a file (`vault_credentials.json`) by default, which includes:

- Unseal keys for the root vault
- Root token for the root vault
- Sub vault token
- Transit token for auto-unseal

## Test Client Example

The test client example (`examples/test_client.rs`) demonstrates how to interact with the web server API to set up and manage vault instances.

### Features

- Complete vault setup flow
- Root and sub vault initialization
- Transit engine setup
- Auto-unseal configuration
- PKI infrastructure setup
- Proper credential management

### Running the Test Client

```bash
# Basic run
cargo run --example test_client

# Restart the sub vault with existing credentials
cargo run --example test_client -- --restart-sub-vault
```

### Implementation Details

The test client:

1. Connects to the web server
2. Checks if credentials already exist
3. Sets up the root vault if needed
4. Unseals the root vault
5. Sets up transit engine
6. Generates a transit token
7. Configures the sub vault with auto-unseal
8. Sets up PKI in the sub vault
9. Saves all credentials for future use

### Credential Management

The test client saves and loads credentials from `vault_credentials.json`, making it easy to:

- Resume from a previous setup
- Restart sub vaults with the correct transit token
- Reuse existing tokens when available

## Integrating with Your Own Applications

To integrate Merka Vault into your own applications, you can:

1. Use the actor-based API directly:

   ```rust
   let (actor, events) = start_vault_actor_with_channel("http://127.0.0.1:8200");

   // Initialize vault
   let init_result = actor.send(InitVault {
       secret_shares: 1,
       secret_threshold: 1
   }).await??;

   // Unseal vault
   let unseal_result = actor.send(UnsealVault {
       keys: init_result.keys
   }).await??;
   ```

2. Build a REST API wrapper similar to the web server example
3. Create a CLI application using the same core functionality

## Best Practices

When using the examples:

1. **Security**:

   - Store unseal keys and tokens securely
   - Use different tokens for different operations
   - Apply principle of least privilege

2. **Operational**:

   - Follow the correct operation sequence
   - Test the end-to-end workflow before production
   - Document your setup process

3. **Integration**:
   - Prefer the actor-based API for thread safety
   - Use the event system for asynchronous monitoring
   - Implement proper error handling

## Troubleshooting

Common issues:

- **Connection errors**: Ensure vault instances are running and accessible
- **Authentication errors**: Verify tokens are correct and have appropriate permissions
- **Initialization errors**: Check if the vault is already initialized
- **Unsealing errors**: Ensure enough unseal keys are provided and they are correct

## References

- [Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Auto-Unseal Documentation](./auto_unseal.md)
- [PKI Documentation](./pki.md)
- [Operations Overview](./operations_overview.md)
