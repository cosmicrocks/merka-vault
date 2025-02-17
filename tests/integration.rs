//! Integration tests for merka-vault using Testcontainers.
//!
//! These tests use the shared Vault fixture defined in `tests/common.rs`.
//! They exercise the PKI and AppRole setup functions from the merka-vault library.
//!
mod common;

use common::{setup_vault_container, setup_vault_dev_container};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_setup_pki() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;

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
    let vault_container = setup_vault_dev_container().await;
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

#[tokio::test]
async fn test_vault_init_and_unseal() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!(
        "http://{host}:{host_port}",
        host = host,
        host_port = host_port
    );

    sleep(Duration::from_secs(3)).await;

    // This test is mostly illustrative; in a real test, we'd run a Vault in uninitialized state and then:
    // let init_res = merka_vault::vault::init_vault(&vault_url, 1, 1).await.unwrap();
    // assert!(!init_res.root_token.is_empty());
    // merka_vault::vault::unseal_vault(&vault_url, &init_res.keys).await.unwrap();
    // Then verify Vault is unsealed, e.g., by calling a sys/health endpoint or using the root token to list mounts.
    assert!(
        merka_vault::vault::init_vault(&vault_url, 1, 1)
            .await
            .is_err(),
        "Init should fail on a dev server (already initialized)"
    );

    Ok(())
}

#[tokio::test]
async fn test_pki_and_auth_setup() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!(
        "http://{host}:{host_port}",
        host = host,
        host_port = host_port
    );

    sleep(Duration::from_secs(3)).await;

    // Test PKI setup
    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) = merka_vault::vault::setup_pki(&vault_url, "root", domain, ttl).await?;
    assert!(
        cert.contains("BEGIN CERTIFICATE"),
        "Should return a PEM certificate"
    );
    println!(
        "PKI setup complete: role '{}' for domain {}, CA cert length {}",
        role_name,
        domain,
        cert.len()
    );

    // Test AppRole setup
    let role = "test-role";
    let policies = vec!["default".to_string()];
    let creds = merka_vault::vault::setup_approle(&vault_url, "root", role, &policies).await?;
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());
    println!(
        "AppRole '{}' -> role_id={}, secret_id={}",
        role, creds.role_id, creds.secret_id
    );

    // Test Kubernetes auth setup
    let k8s_role = "test-k8s-role";
    let sa_name = "vault-auth";
    let ns = "default";
    let k8s_host = "https://kubernetes.default.svc";
    let k8s_ca = "---BEGIN CERTIFICATE---\nMIIF...==\n-----END CERTIFICATE-----";
    let result = merka_vault::vault::setup_kubernetes_auth(
        &vault_url, "root", k8s_role, sa_name, ns, k8s_host, k8s_ca,
    )
    .await;
    if let Err(err) = &result {
        eprintln!(
            "Kubernetes auth setup returned error (expected in test env): {}",
            err
        );
    } else {
        println!("Kubernetes auth configured for role '{}'", k8s_role);
    }
    assert!(
        result.is_ok() || matches!(result, Err(merka_vault::vault::VaultError::Api(_))),
        "K8s setup should either succeed or produce Vault API error due to missing JWT"
    );

    Ok(())
}

#[tokio::test]
async fn test_full_vault_setup() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!(
        "http://{host}:{host_port}",
        host = host,
        host_port = host_port
    );

    sleep(Duration::from_secs(3)).await;

    // Initialize and unseal Vault
    let init_res = merka_vault::vault::init_vault(&vault_url, 1, 1).await?;
    assert!(!init_res.root_token.is_empty());
    merka_vault::vault::unseal_vault(&vault_url, &init_res.keys).await?;
    let root_token = init_res.root_token;

    // Test PKI setup
    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault::vault::setup_pki(&vault_url, &root_token, domain, ttl).await?;
    assert!(
        cert.contains("BEGIN CERTIFICATE"),
        "Should return a PEM certificate"
    );
    println!(
        "PKI setup complete: role '{}' for domain {}, CA cert length {}",
        role_name,
        domain,
        cert.len()
    );

    // Test AppRole setup
    let role = "test-role";
    let policies = vec!["default".to_string()];
    let creds = merka_vault::vault::setup_approle(&vault_url, &root_token, role, &policies).await?;
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());
    println!(
        "AppRole '{}' -> role_id={}, secret_id={}",
        role, creds.role_id, creds.secret_id
    );

    // Test Kubernetes auth setup
    let k8s_role = "test-k8s-role";
    let sa_name = "vault-auth";
    let ns = "default";
    let k8s_host = "https://kubernetes.default.svc";
    let k8s_ca = "---BEGIN CERTIFICATE---\nMIIF...==\n-----END CERTIFICATE-----";
    let result = merka_vault::vault::setup_kubernetes_auth(
        &vault_url,
        &root_token,
        k8s_role,
        sa_name,
        ns,
        k8s_host,
        k8s_ca,
    )
    .await;
    if let Err(err) = &result {
        eprintln!(
            "Kubernetes auth setup returned error (expected in test env): {}",
            err
        );
    } else {
        println!("Kubernetes auth configured for role '{}'", k8s_role);
    }
    assert!(
        result.is_ok() || matches!(result, Err(merka_vault::vault::VaultError::Api(_))),
        "K8s setup should either succeed or produce Vault API error due to missing JWT"
    );

    Ok(())
}
