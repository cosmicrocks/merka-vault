# SQLite Database Integration

This document explains the SQLite integration in Merka Vault, focusing on how credentials and vault relationships are stored and managed.

## Overview

Merka Vault uses SQLite for persistent storage of vault credentials and relationships. This replaces the previous JSON file-based storage system, providing better transactional integrity, concurrent access, and structured data management.

## Database Schema

The SQLite database contains the following tables:

### vault_credentials

This table stores the credentials for vault instances:

| Column           | Type    | Description                   |
| ---------------- | ------- | ----------------------------- |
| id               | INTEGER | Primary key                   |
| root_unseal_keys | TEXT    | JSON array of unseal keys     |
| root_token       | TEXT    | Root vault token              |
| sub_token        | TEXT    | Sub vault token               |
| transit_token    | TEXT    | Token for transit auto-unseal |

### vault_relationships

This table stores the relationships between vaults, specifically which root vault is responsible for unsealing which sub vault:

| Column    | Type    | Description               |
| --------- | ------- | ------------------------- |
| id        | INTEGER | Primary key               |
| sub_addr  | TEXT    | Address of the sub vault  |
| root_addr | TEXT    | Address of the root vault |

## DatabaseManager

The `DatabaseManager` struct provides an interface for interacting with the SQLite database:

```rust
pub struct DatabaseManager {
    pool: Arc<DbPool>,
}
```

It uses a connection pool to manage database connections efficiently, allowing for concurrent access.

## Key Operations

### Initialization

```rust
let db_manager = DatabaseManager::new("merka_vault.db")?;
```

This initializes the database, creating the tables if they don't exist already.

### Saving Credentials

```rust
let credentials = VaultCredentials {
    root_unseal_keys: vec!["key1".to_string(), "key2".to_string()],
    root_token: "root-token".to_string(),
    sub_token: "sub-token".to_string(),
    transit_token: "transit-token".to_string(),
};

db_manager.save_vault_credentials(&credentials)?;
```

The `save_vault_credentials` method will either insert new credentials or update existing ones based on whether records already exist in the database.

### Loading Credentials

```rust
let credentials = db_manager.load_vault_credentials()?;
```

This loads the stored credentials from the database. If no credentials exist, it returns a default empty `VaultCredentials` struct.

### Managing Unsealer Relationships

These methods handle the relationships between root and sub vaults for auto-unsealing:

```rust
// Save relationship
db_manager.save_unsealer_relationship("http://127.0.0.1:8202", "http://127.0.0.1:8200")?;

// Load all relationships
let relationships = db_manager.load_unsealer_relationships()?;

// Delete relationship
db_manager.delete_unsealer_relationship("http://127.0.0.1:8202")?;
```

## Integration with VaultActor

The `VaultActor` can be configured to use the `DatabaseManager` for persistent storage:

```rust
let db_manager = DatabaseManager::new("merka_vault.db")?;
let actor = VaultActor::new("http://127.0.0.1:8200", None)
    .with_database(db_manager);
```

When a `DatabaseManager` is attached to a `VaultActor`:

1. Credentials are automatically loaded/saved during initialization and operations
2. Unsealer relationships are tracked for auto-unseal functionality
3. Events can persist state changes to the database

## CLI Integration

The CLI commands automatically use the database for storage:

```bash
# Start server with specific database path
merka-vault server --db-path="custom_path.db"
```

## Web Server Integration

The web server uses the database for all credential and relationship management:

```rust
// In start_server function
let db_manager = DatabaseManager::new(db_path)?;
let db_manager_arc = Arc::new(db_manager);

// Create actor with database
let actor = VaultActor::new(vault_addr, Some(tx.clone()))
    .with_database(DatabaseManager::new(db_path).unwrap());
```

## Migration from JSON Files

If you're migrating from the old JSON-based storage:

1. The server automatically checks for and removes old `vault_credentials.json` files
2. You can use the `/api/sync_token` endpoint to sync existing tokens to the database
3. Relationships need to be re-added using the appropriate API endpoints

## Best Practices

1. **Backups**: Regularly back up the SQLite database file
2. **File Permissions**: Ensure the database file has appropriate permissions
3. **Transactions**: Use transactions for multiple operations
4. **Security**: Consider encrypting the database file in sensitive environments

## Error Handling

The `DatabaseManager` returns `SQLiteResult` types for database operations, which should be properly handled:

```rust
match db_manager.save_vault_credentials(&credentials) {
    Ok(_) => info!("Credentials saved successfully"),
    Err(e) => error!("Failed to save credentials: {}", e),
}
```

## Advanced Usage

### Custom Database Paths

You can specify a custom database path:

```rust
let db_manager = DatabaseManager::new("/path/to/custom/db.sqlite")?;
```

### Accessing Raw Connection Pool

For advanced operations, you can access the underlying connection pool:

```rust
let pool = db_manager.get_pool();
```

## Troubleshooting

Common SQLite-related issues:

- **Permission denied**: Check file system permissions
- **Disk space**: Ensure sufficient disk space
- **Corruption**: If database corruption occurs, restore from backup
- **Concurrency**: SQLite has limitations with concurrent writes
