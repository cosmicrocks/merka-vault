# merka-vault

[![Crates.io](https://img.shields.io/crates/v/merka-vault.svg)](https://crates.io/crates/merka-vault)
[![Docs.rs](https://docs.rs/merka-vault/badge.svg)](https://docs.rs/merka-vault)
[![Build](https://img.shields.io/github/actions/workflow/status/cosmicrocks/merka-vault/ci.yml?branch=main)](https://github.com/cosmicrocks/merka-vault/actions)
[![License: MIT or Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

**merka-vault** is a Rust library and CLI tool for bootstrapping HashiCorp Vault. It automates initialization (seal/unseal), configures a PKI secrets engine, and sets up various authentication methods. It integrates with `merka-core` or works as a standalone tool.

## Features

- **Vault Initialization & Unsealing** – Initialize and unseal Vault using Shamir's secret shares.
- **PKI Setup** – Enable Vault’s PKI engine and create a self-signed root CA or intermediate CA.
- **AppRole Authentication** – Enable AppRole and create roles for applications.
- **Kubernetes Authentication** – Use the Kubernetes auth method to trust service account tokens.
- **CLI Tool** – Command-line management for initialization, PKI, and auth configuration.
- **Actor Integration** – Asynchronous Vault management using `VaultActor` with Actix.

## Usage (CLI)

1. Initialize and unseal Vault:

```sh
merka-vault init --secret-shares 3 --secret-threshold 2
```

2. Set up PKI and authentication:

```sh
merka-vault setup-pki --domain my-org.com --ttl 4380h
merka-vault auth approle --role-name myapp --policies default,my-policy
```

## Usage (Rust)

- Build the project: `just build`
- Run tests: `just test`

## Development

Example (macOS):

```sh
# Install Rust
curl https://sh.rustup.rs -sSf | sh

# Install Just
brew install just

# Run tests
just test
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Licensed under MIT or Apache 2.0. See [LICENSE](LICENSE) for details.

## Code of Conduct

This project adheres to a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to abide by its terms.
