//! Integration tests for merka-vault using Testcontainers.
//!
//! These tests use the shared Vault fixture defined in `tests/common.rs`.
//! They exercise the PKI and AppRole setup functions from the merka-vault library.
//! The tests run only if the environment variable
//! `MERKA_VAULT_RUN_INTEGRATION_TESTS` is set; otherwise they are skipped.

mod common;

use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_setup_pki() -> Result<(), Box<dyn std::error::Error>> {
    let vault = common::VaultFixture::new().await;

    let vault_addr = vault.vault_addr();

    // Give Vault a few seconds to be extra sure it is ready.
    sleep(Duration::from_secs(3)).await;

    // Call the PKI setup function from your library.
    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) = merka_vault::vault::setup_pki(&vault_addr, "root", domain, ttl).await?;

    println!("CA Certificate:\n{}", cert);
    println!("PKI role name: {}", role_name);

    // Verify that the returned certificate contains the PEM header.
    assert!(cert.contains("BEGIN CERTIFICATE"));
    // The role name should be the domain with dots replaced by hyphens.
    assert_eq!(role_name, domain.replace('.', "-"));

    Ok(())
}

#[tokio::test]
async fn test_setup_approle() -> Result<(), Box<dyn std::error::Error>> {
    let vault = common::VaultFixture::new().await;

    let vault_addr = vault.vault_addr();

    sleep(Duration::from_secs(3)).await;

    // Test the AppRole setup.
    let role_name = "test-role";
    let policies = vec!["default".to_string()];
    let creds =
        merka_vault::vault::setup_approle(&vault_addr, "root", role_name, &policies).await?;

    println!(
        "AppRole credentials: role_id: {}, secret_id: {}",
        creds.role_id, creds.secret_id
    );
    // Verify that non‑empty RoleID and SecretID are returned.
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());

    Ok(())
}
