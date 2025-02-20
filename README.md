# merka-vault

[![Crates.io](https://img.shields.io/crates/v/merka-vault.svg)](https://crates.io/crates/merka-vault)
[![Docs.rs](https://docs.rs/merka-vault/badge.svg)](https://docs.rs/merka-vault)
[![Build](https://img.shields.io/github/actions/workflow/status/cosmicrocks/merka-vault/ci.yml?branch=main)](https://github.com/cosmicrocks/merka-vault/actions)
[![License: MIT or Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

**merka-vault** is a Rust library and CLI for bootstrapping HashiCorp Vault. It automates initialization (seal/unseal), configures a PKI secrets engine, and sets up authentication methods (Token, AppRole, Kubernetes). It can integrate with the `merka-core` actor framework or serve as a standalone tool.

## Features

- **Vault Initialization & Unsealing** – Initialize and unseal Vault using Shamir's secret shares [oai_citation_attribution:15‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/concepts/seal#:~:text=Shamir%20seals) [oai_citation_attribution:16‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/concepts/seal#:~:text=This%20is%20the%20unseal%20process%3A,and%20decrypt%20the%20root%20key).
- **PKI Setup** – Enable Vault’s PKI engine and create a self-signed root CA (or use an intermediate CA) [oai_citation_attribution:17‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/secrets/pki/setup#:~:text=3,Vault%20a%20signed%20intermediate%20CA).
- **AppRole Authentication** – Enable AppRole and create roles for applications, retrieving RoleID/SecretID [oai_citation_attribution:18‡openbao.org](https://openbao.org/docs/auth/approle/#:~:text=3,the%20role) [oai_citation_attribution:19‡openbao.org](https://openbao.org/docs/auth/approle/#:~:text=4,identifier%20under%20the%20role).
- **Kubernetes Authentication** – Use the Kubernetes auth method to trust service account tokens [oai_citation_attribution:20‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/auth/kubernetes#:~:text=The%20,token%20into%20a%20Kubernetes%20Pod).
- **CLI Tool** – Manage Vault from the command line to handle initialization, unsealing, PKI setup, and auth configuration.
- **Actor Integration** – Manage Vault asynchronously using the `VaultActor` in Rust (with Actix).

## Usage (CLI)

1. Initialize Vault (if needed), unseal it, and export the root token:

```sh
merka-vault init --secret-shares 3 --secret-threshold 2
merka-vault unseal --key=<UNSEAL_KEY_1> --key=<UNSEAL_KEY_2>
export VAULT_TOKEN=<ROOT_TOKEN>
```

2. Set up PKI and authentication methods:

```sh
merka-vault setup-pki --domain my-org.com --ttl 4380h
merka-vault auth approle --role-name myapp --policies default,my-policy
```

3. Log in with RoleID/SecretID:

```sh
vault write auth/approle/login \
  role_id="<ROLE_ID>" \
  secret_id="<SECRET_ID>"
```

4. Configure Kubernetes auth:

```sh
merka-vault auth kubernetes --role-name myservice \
  --service-account vault-auth --namespace apps \
  --kubernetes-host https://$KUBERNETES_PORT_443_TCP_ADDR:443 \
  --kubernetes-ca-cert "$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)"
```

Then log in with Kubernetes tokens:

```sh
VAULT_ADDR=http://vault:8200 vault login -method=kubernetes \
  role="myservice" \
  jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

## Usage (Rust)

- Use `just build` to build the project.
- Use `just test` to run tests.

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

## Configuration

`merka-vault` can be configured using environment variables or a configuration file. Here are some common configurations:

- `VAULT_ADDR`: The address of the Vault server.
- `VAULT_TOKEN`: The root token for Vault.

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

## License

This project is licensed under either the MIT or Apache 2.0 license, at your option. See the [LICENSE](LICENSE) file for details.

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
