# Merka Vault Examples

This document describes the example code provided in the Merka Vault project, focusing on the web server and test client implementations.

## Web Server Example

The web server example (`examples/web_server.rs`) demonstrates a complete implementation of a REST API and Socket.IO server for managing Vault instances with the following capabilities:

- Vault initialization and unsealing
- Transit-based auto-unseal setup
- PKI infrastructure configuration
- WebSocket events for real-time operation status
- SQLite-based credential storage

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
| `/api/sync_token`                | POST   | Sync an existing token with the database                     |

### Running the Web Server

```bash
# Run using the CLI command
cargo run -- server

# Or run the example directly
cargo run --example web_server
```

The server will start on port 8080 by default. You can then interact with it using any HTTP client or WebSocket client for real-time events.

### Server Implementation Details

The web server uses several important technologies:

1. **Actix Web** for the HTTP server implementation
2. **Actix Actor** for handling vault operations concurrently
3. **Socket.IO** for real-time event notifications
4. **SQLite** for credential storage
5. **Tokio's LocalSet** for handling Socket.IO tasks

#### Important Technical Notes

- The SocketIo library requires a `tokio::task::LocalSet` context to operate correctly. All socket operations must use `tokio::task::spawn_local` instead of regular `tokio::spawn`.
- The server is designed to run within a LocalSet, which allows the use of non-Send futures.
- The VaultActor is initialized for each worker thread to handle concurrent connections.

### Socket.IO Events

The web server provides Socket.IO events for real-time monitoring:

- `vault_init` - Vault initialization event
- `vault_unseal` - Vault unsealing event
- `vault_seal` - Vault sealing event
- `transit_setup` - Transit engine setup event
- `pki_setup` - PKI setup event
- `auto_unseal` - Auto-unseal configuration event
- `dependency_check` - Dependency check event
- `vault_status` - Status update event
- `vaults_listed` - List of known vaults updated

### Vault Credentials

The web server uses SQLite for all credential storage:

- **Database Location**: By default, credentials are stored in a SQLite database file (`merka_vault.db`)
- **Data Stored**:
  - Unseal keys for the root vault
  - Root token for the root vault
  - Sub vault token
  - Transit token for auto-unseal
  - Unsealer relationships between vaults

This replaces the previous JSON-based file storage system, providing better data integrity, concurrent access, and proper transaction support.

## Test Client Example

The test client example (`examples/test_client.rs`) demonstrates how to interact with the web server API to set up and manage vault instances.

### Features

- Complete vault setup flow
- Root and sub vault initialization
- Transit engine setup
- Auto-unseal configuration
- PKI infrastructure setup
- Credential management via SQLite

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
2. Checks if credentials already exist in the database
3. Sets up the root vault if needed
4. Unseals the root vault
5. Sets up transit engine
6. Generates a transit token
7. Configures the sub vault with auto-unseal
8. Sets up PKI in the sub vault
9. Saves all credentials to the SQLite database

### Credential Management

The SQLite database provides several advantages over the previous file-based storage:

- **Transaction support** - Ensures data integrity when updating credentials
- **Concurrent access** - Multiple processes can safely read/write
- **Structured storage** - Proper schema for all credential data
- **Relationship tracking** - Stores associations between root and sub vaults

## Integrating with Your Own Applications

To integrate Merka Vault into your own applications, you can:

1. Use the actor-based API with SQLite storage:

   ```rust
   // Initialize database
   let db_manager = DatabaseManager::new("merka_vault.db").unwrap();

   // Create actor with database
   let (tx, rx) = broadcast::channel(100);
   let actor = VaultActor::new("http://127.0.0.1:8200", Some(tx))
       .with_database(db_manager);
   let actor_addr = actor.start();

   // Initialize vault
   let init_result = actor_addr.send(InitVault {
       secret_shares: 1,
       secret_threshold: 1
   }).await??;

   // Unseal vault
   let unseal_result = actor_addr.send(UnsealVault {
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
   - Consider encrypting the SQLite database for sensitive environments

2. **Operational**:

   - Follow the correct operation sequence
   - Test the end-to-end workflow before production
   - Document your setup process
   - Regularly back up the SQLite database

3. **Integration**:
   - Prefer the actor-based API for thread safety
   - Use the event system for asynchronous monitoring
   - Implement proper error handling
   - Use proper transaction handling for database operations

## Troubleshooting

Common issues:

- **Connection errors**: Ensure vault instances are running and accessible
- **Authentication errors**: Verify tokens are correct and have appropriate permissions
- **Initialization errors**: Check if the vault is already initialized
- **Unsealing errors**: Ensure enough unseal keys are provided and they are correct
- **Socket.IO errors**: Make sure Socket.IO operations are running in a `tokio::task::LocalSet` context
- **Database errors**: Check file permissions and disk space for the SQLite database

## References

- [Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Auto-Unseal Documentation](./auto_unseal.md)
- [PKI Documentation](./pki.md)
- [Operations Overview](./operations_overview.md)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Socket.IO Documentation](https://socket.io/docs/v4/)

## Integration Testing

The project includes comprehensive integration tests that verify the functionality of the examples, especially the test client. These tests are located in the `tests/test_integration.rs` file.

### Test Database Operations

The `
