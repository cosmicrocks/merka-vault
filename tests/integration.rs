//! Integration tests for merka-vault using Testcontainers.
//!
//! These tests use the shared Vault fixture defined in `tests/common.rs`.
//! They exercise the PKI and AppRole setup functions from the merka-vault library.
//! The tests run only if the environment variable
//! `MERKA_VAULT_RUN_INTEGRATION_TESTS` is set; otherwise they are skipped.

mod common;

use common::setup_vault_container;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_setup_pki() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container().await;

    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();

    let vault_url = format!(
        "http://{host}:{host_port}",
        host = host,
        host_port = host_port
    );

    // Give Vault a few seconds to be extra sure it is ready.
    sleep(Duration::from_secs(3)).await;

    // Call the PKI setup function from your library.
    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) = merka_vault::vault::setup_pki(&vault_url, "root", domain, ttl).await?;

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
    let vault_container = setup_vault_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!(
        "http://{host}:{host_port}",
        host = host,
        host_port = host_port
    );

    sleep(Duration::from_secs(3)).await;

    // Test the AppRole setup.
    let role_name = "test-role";
    let policies = vec!["default".to_string()];
    let creds = merka_vault::vault::setup_approle(&vault_url, "root", role_name, &policies).await?;

    println!(
        "AppRole credentials: role_id: {}, secret_id: {}",
        creds.role_id, creds.secret_id
    );
    // Verify that non‑empty RoleID and SecretID are returned.
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());

    Ok(())
}
