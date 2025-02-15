# merka-vault

[![Crates.io](https://img.shields.io/crates/v/merka-vault.svg)](https://crates.io/crates/merka-vault)
[![Docs.rs](https://docs.rs/merka-vault/badge.svg)](https://docs.rs/merka-vault)
[![CI](https://github.com/merka-org/merka-vault/actions/workflows/ci.yaml/badge.svg)](https://github.com/merka-org/merka-vault/actions)
[![License: MIT or Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

**merka-vault** is a Rust library and CLI for bootstrapping HashiCorp Vault. It automates Vault server initialization (seal/unseal process), configures a PKI secrets engine, and sets up authentication methods (Token, AppRole, Kubernetes). It is designed to be integrated with the `merka-core` actor framework, but can also be used as a standalone command-line tool.

## Features

- **Vault Initialization & Unsealing** – Initialize a new Vault and obtain unseal keys and the initial root token, then unseal the Vault using Shamir's secret shares [oai_citation_attribution:15‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/concepts/seal#:~:text=Shamir%20seals) [oai_citation_attribution:16‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/concepts/seal#:~:text=This%20is%20the%20unseal%20process%3A,and%20decrypt%20the%20root%20key).
- **PKI Setup** – Enable the PKI engine and generate a self-signed root CA for your domain (or use an intermediate CA) [oai_citation_attribution:17‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/secrets/pki/setup#:~:text=3,Vault%20a%20signed%20intermediate%20CA). A default role is created to allow issuing certificates.
- **AppRole Authentication** – Enable AppRole auth method and create roles for applications. Retrieve RoleID/SecretID for your AppRole to use in automated Vault login [oai_citation_attribution:18‡openbao.org](https://openbao.org/docs/auth/approle/#:~:text=3,the%20role) [oai_citation_attribution:19‡openbao.org](https://openbao.org/docs/auth/approle/#:~:text=4,identifier%20under%20the%20role).
- **Kubernetes Authentication** – Enable the Kubernetes auth method and configure Vault to trust your cluster’s service account tokens [oai_citation_attribution:20‡developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/auth/kubernetes#:~:text=The%20,token%20into%20a%20Kubernetes%20Pod). Bind a Kubernetes service account to Vault policies so that apps in the cluster can authenticate.
- **CLI Tool** – Use the provided `merka-vault` CLI to perform these operations from the command line (useful for one-time setup or in scripts).
- **Actor Integration** – Use the `VaultActor` in your Rust code (with Actix) to manage Vault asynchronously (suitable for integration with systems like merka-core).

## Usage (CLI)

Make sure you have access to a Vault server (for testing, you can use `docker-compose up -d vault` to start a dev server).

Initialize Vault (if not already initialized):

```sh
merka-vault init --secret-shares 3 --secret-threshold 2
merka-vault unseal --key=<UNSEAL_KEY_1> --key=<UNSEAL_KEY_2>

export VAULT_TOKEN=<ROOT_TOKEN>
merka-vault setup-pki --domain my-org.com --ttl 4380h
merka-vault auth approle --role-name myapp --policies default,my-policy

# Example: login with RoleID/SecretID using Vault CLI or HTTP API
vault write auth/approle/login role_id="<ROLE_ID>" secret_id="<SECRET_ID>"

merka-vault auth kubernetes --role-name myservice \
  --service-account vault-auth --namespace apps \
  --kubernetes-host https://$KUBERNETES_PORT_443_TCP_ADDR:443 \
  --kubernetes-ca-cert "$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)"

  # Example within a pod:
VAULT_ADDR=http://vault:8200 vault login -method=kubernetes \
    role="myservice" \
    jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

## Usage (Rust)

just build

just test

## Development

```sh
# Install nix
curl -L https://nixos.org/nix/install | sh

nix-store --gc
nix --accept-flake-config profile install github:juspay/omnix
```
