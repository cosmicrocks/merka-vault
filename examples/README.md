# Merka Vault Examples

This directory contains examples to demonstrate how to use the Merka Vault library in real-world scenarios.

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

- `POST /api/initialize` - Initialize a Vault
- `POST /api/unseal` - Unseal a Vault
- `GET /api/status` - Check Vault status
- `POST /api/setup_pki` - Set up PKI infrastructure
- `POST /api/autounseal` - Trigger auto-unseal

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
2. Connect to Socket.IO to receive events
3. Run a complete workflow for setting up and monitoring Vaults

### Running the Test Client Example

Prerequisites:

- Web server example is running
- Vault instances are running via Docker Compose

Steps:

1. Run the test client example:

   ```
   cargo run --example test_client
   ```

2. Watch the logs to see the events being received from the web server.

## Integration Testing

The examples can also be used for integration testing. See `tests/example_test.rs` for an example of how to use the web server and test client together as an integration test.

To run the integration test:

```
cargo test --test example_test -- --ignored
```

Note: The test is marked as `#[ignore]` by default since it requires the Docker Compose Vault instances to be running.
