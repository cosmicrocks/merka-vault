# Vault PKI Secrets Engine

## Overview

The PKI (Public Key Infrastructure) secrets engine in HashiCorp Vault allows you to create a certificate authority (CA) and generate certificates. This document describes how to set up and manage a complete PKI infrastructure using Vault, including root CAs, intermediate CAs, and certificate issuance.

## Why Use Vault for PKI?

- **Dynamic Certificates**: Generate certificates on-demand with configurable TTLs
- **Built-in Revocation**: Manage certificate revocation lists (CRLs) automatically
- **API-driven**: Fully automate certificate operations via API
- **Role-based Access Control**: Restrict which entities can issue which types of certificates
- **CA Hierarchies**: Support for multi-level CA hierarchies with proper security boundaries

## Architecture

![PKI Architecture](./images/pki_architecture.png)

The PKI infrastructure in Vault typically follows this structure:

1. A root CA that is kept highly secure and used infrequently
2. One or more intermediate CAs that issue certificates for actual use
3. Certificate roles that define what types of certificates can be issued
4. Clients that request and use the certificates

## PKI Components

- **Root CA**: The top-level certificate authority that signs intermediate CAs
- **Intermediate CA**: The signing authority for end-entity certificates
- **Roles**: Templates that define certificate parameters (domains, TTLs, key usage, etc.)
- **Certificates**: The resulting TLS/SSL certificates used by applications
- **CRL**: Certificate Revocation List for invalidating certificates

## PKI Setup Flow

### 1. Root CA Setup

First, you set up a root Certificate Authority:

```rust
// Setup root PKI engine
let vault_url = "http://your-vault:8200";
let token = "root_token";
let domain = "example.com";
let ttl = "87600h"; // 10 years
let use_intermediate = false;

// This creates a root CA and configures a role
let (ca_cert, role_name) = merka_vault::vault::pki::setup_pki(
    &vault_url,
    &token,
    domain,
    ttl,
    use_intermediate,
    None,
    None
).await?;
```

This performs:

- Enabling the PKI secrets engine
- Generating a self-signed CA certificate
- Configuring URLs for CRL distribution and issuing certificates
- Creating a role that can issue certificates for the specified domain

### 2. Intermediate CA Setup (Same Vault)

For improved security, you should use an intermediate CA for issuing certificates:

```rust
// Setup intermediate CA in the same Vault
let vault_url = "http://your-vault:8200";
let token = "root_token";
let domain = "example.com";
let ttl = "43800h"; // 5 years
let use_intermediate = true;

// This creates a root CA, an intermediate CA, and configures a role
let (ca_chain, role_name) = merka_vault::vault::pki::setup_pki(
    &vault_url,
    &token,
    domain,
    ttl,
    use_intermediate,
    None,
    None
).await?;
```

This performs additional steps:

- Setting up a second PKI secrets engine for the intermediate CA
- Generating an intermediate CA CSR
- Signing the CSR with the root CA
- Configuring the intermediate to issue certificates

### 3. Two-Vault Intermediate CA Setup

For even better security, you can use separate Vaults for root and intermediate CAs:

```rust
// Setup with root CA in one Vault and intermediate in another
let root_vault_url = "http://root-vault:8200";
let int_vault_url = "http://int-vault:8200";
let root_token = "root_token_for_root_vault";
let int_token = "root_token_for_int_vault";
let domain = "example.com";
let ttl = "43800h"; // 5 years

// This sets up a root CA in root_vault and an intermediate CA in int_vault
let (ca_chain, role_name) = merka_vault::vault::pki::setup_pki_intermediate(
    &root_vault_url,
    &root_token,
    &int_vault_url,
    &int_token,
    domain,
    ttl
).await?;
```

This implements a more secure workflow:

- Root CA is confined to a separate, potentially air-gapped Vault
- The intermediate Vault is used for regular certificate issuance
- The root Vault only needs to come online to rotate/reissue the intermediate CA

### 4. Issuing Certificates

Once your PKI infrastructure is set up, you can issue certificates:

```rust
// Issue a certificate from the configured role
let domain = "example.com"; // The role name is based on this
let common_name = "service.example.com";
let ttl = "720h"; // 30 days
let vault_url = "http://your-vault:8200";
let token = "token_with_pki_access";

let (cert, private_key) = merka_vault::vault::pki::issue_certificate(
    &vault_url,
    &token,
    &format!("{}-int", domain.replace('.', "-")), // Role name
    common_name,
    Some(ttl)
).await?;
```

This:

- Requests a new certificate from the specified Vault role
- Returns the certificate and private key
- Sets the appropriate TTL for the certificate
- Includes the correct certificate chain

## Implementation in `merka-vault`

The PKI functionality in `merka-vault` is implemented in the `vault::pki` module.

### Key Functions

- `setup_pki`: Sets up root CA with optional same-vault intermediate
- `setup_pki_intermediate`: Sets up a root CA in one Vault and an intermediate in another
- `issue_certificate`: Issues end-entity certificates using a configured role

### Root PKI Setup Process

1. **Mount PKI Engine**: A PKI secrets engine is mounted at path `/pki/`
2. **Generate Root CA**: A self-signed root CA is generated with the specified TTL
3. **Configure CA URLs**: CRL distribution and issuing certificate URLs are configured
4. **Create Role**: A role is created to define what certificates can be issued

### Intermediate CA Setup Process

1. **Mount Intermediate PKI Engine**: A PKI secrets engine is mounted at path `/pki_int/`
2. **Generate CSR**: A certificate signing request is generated
3. **Sign with Root CA**: The root CA signs the intermediate CSR
4. **Import Certificate**: The signed certificate is imported into the intermediate PKI engine
5. **Configure CA URLs**: CRL distribution and issuing certificate URLs are configured
6. **Create Role**: A role is created to define what certificates can be issued

### Certificate Issuance Process

1. **Request Certificate**: A certificate request is sent to the configured role
2. **Validation**: The Vault validates the request against the role parameters
3. **CA Signing**: The CA signs the certificate with appropriate extensions
4. **Return Certificate**: The certificate, key, and CA chain are returned

## Best Practices

1. **Secure Root CA**:

   - Keep the root CA offline when not needed
   - Set a long TTL for the root CA (10+ years)
   - Use a separate Vault instance for the root CA

2. **Intermediate CA Management**:

   - Set a moderate TTL (1-5 years)
   - Plan for periodic rotation
   - Consider multiple intermediates for different purposes

3. **Certificate Configuration**:

   - Set appropriate TTLs for end-entity certificates (days/weeks/months)
   - Restrict domains in roles to only those needed
   - Use proper key usage and extended key usage parameters

4. **Access Control**:

   - Limit who can access the root CA
   - Apply principle of least privilege for intermediate CAs
   - Use dedicated tokens or authentication methods for certificate issuance

5. **Monitoring**:
   - Monitor certificate expirations
   - Rotate certificates before they expire
   - Set up alerts for nearing expirations

## Using PKI with CLI

The `merka-vault` CLI supports PKI operations:

```bash
# Setup root CA
merka-vault --vault-addr=http://vault:8200 pki setup \
  --token=root_token \
  --common-name=example.com \
  --ttl=87600h

# Setup with intermediate
merka-vault --vault-addr=http://vault:8200 pki setup \
  --token=root_token \
  --common-name=example.com \
  --ttl=43800h \
  --use-intermediate

# Setup with intermediate in separate Vault
merka-vault --vault-addr=http://root-vault:8200 pki setup \
  --token=root_token \
  --common-name=example.com \
  --ttl=43800h \
  --intermediate-addr=http://int-vault:8200 \
  --intermediate-token=int_token

# Issue certificate
merka-vault --vault-addr=http://vault:8200 pki issue \
  --token=pki_token \
  --domain=example.com \
  --common-name=service.example.com \
  --ttl=720h \
  --output=cert.pem
```

## Troubleshooting

### Common Issues

1. **Certificate Chain Problems**:

   - Ensure the certificate includes the full chain
   - Verify the root CA is trusted by clients
   - Check that intermediate CAs are included in the chain

2. **Name Constraints**:

   - Verify the certificate's common name matches the role constraints
   - Check that SANs (Subject Alternative Names) are properly configured
   - Ensure the role allows the requested domains

3. **TTL Issues**:
   - Ensure the requested TTL doesn't exceed the role's max TTL
   - Check that the intermediate CA's TTL doesn't limit certificate TTL
   - Verify certificates aren't expired

### Logs to Check

- Look for errors in the Vault audit logs related to PKI operations
- Check the detailed error messages returned from failed certificate requests
- For TLS errors, examine client-side SSL/TLS error logs

## Advanced Topics

### OCSP Responders

Vault can function as an OCSP (Online Certificate Status Protocol) responder:

```rust
// Enable OCSP responder
let enable_ocsp = true;
merka_vault::vault::pki::setup_pki(
    &vault_url, &token, domain, ttl, use_intermediate, None, None, enable_ocsp
).await?;
```

### Cross-Signing CAs

For CA rotation, you might need to cross-sign certificates:

```rust
// Generate a new root CA but have it trusted by the old one
merka_vault::vault::pki::cross_sign_ca(
    &vault_url, &token, &old_ca_path, &new_ca_path
).await?;
```

### Custom Certificate Profiles

Create specialized certificate profiles for different use cases:

```rust
// Create a specialized role for client authentication
merka_vault::vault::pki::create_client_auth_role(
    &vault_url, &token, "client-auth-role", &allowed_domains, ttl
).await?;
```

## References

- [HashiCorp Vault PKI Secrets Engine](https://www.vaultproject.io/docs/secrets/pki)
- [NIST SP 800-57: Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
