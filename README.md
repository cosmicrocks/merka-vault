# Merka-Vault

A Rust-based tool for managing and automating HashiCorp Vault operations.

## Features

- Initialize Vault instances
- Unseal Vault instances
- Set up PKI infrastructure
- Auto-unseal support
- Interactive setup wizard

## CLI Usage

```
merka-vault [OPTIONS] [COMMAND]
```

### Global Options

- `-a, --address <ADDR>`: Vault server address (default: "http://127.0.0.1:8200")
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Display help information

### Commands

#### setup

Run the interactive setup wizard to configure vaults.

```
merka-vault setup
```

This wizard will:

- Detect if you're running vaults locally (via Docker or direct install)
- Guide you through root and sub vault configuration
- Automatically set up auto-unsealing
- Configure PKI infrastructure

#### init

Initialize a new Vault instance.

```
merka-vault init [OPTIONS]
```

Options:

- `-s, --shares <SHARES>`: Number of key shares to split the root key into (default: 5)
- `-t, --threshold <THRESHOLD>`: Number of shares required to reconstruct the root key (default: 3)

#### unseal

Unseal a Vault instance using key shares.

```
merka-vault unseal [OPTIONS] [KEY]
```

Options:

- `-k, --key <KEY>`: Provide unseal key (can be repeated for multiple keys)

#### pki-setup

Set up PKI infrastructure.

```
merka-vault pki-setup [OPTIONS]
```

Options:

- `-r, --role <ROLE_NAME>`: Role name for PKI (default: "cert-issuer")

#### auto-unseal

Configure and perform auto-unsealing.

```
merka-vault auto-unseal [OPTIONS]
```

Options:

- `-r, --recovery-shares <SHARES>`: Number of recovery shares (default: 3)

## Programmatic Usage

The same operations available via CLI can be performed programmatically using the `VaultActor`:

```rust
let (actor, mut events) = start_vault_actor_with_channel("http://127.0.0.1:8200");
let result = actor.send(InitVault {
    secret_shares: 5,
    secret_threshold: 3
}).await?;
```

For more details, see the API documentation.

## Development

Example (macOS):

```sh
# for private repos dependencies
git config --global credential.helper osxkeychain

# Install Rust
curl https://sh.rustup.rs -sSf | sh

# Install Just
brew install just

# Run tests
just test

# Start local setup
just compose-up

# Build the project
just build
cargo build --all

# Setup vaults with the interactive wizard (recommended)
./target/debug/merka-vault setup

# Alternatively, use the individual commands
./target/debug/merka-vault setup-root
VAULT_TOKEN=<UNWRAPPED_TOKEN> docker-compose up -d sub-vault
./target/debug/merka-vault setup-sub --root-token <ROOT_TOKEN>
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Licensed under MIT or Apache 2.0. See [LICENSE](LICENSE) for details.

## Code of Conduct

This project adheres to a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to abide by its terms.
