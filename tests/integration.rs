mod common;
use common::{setup_vault_container, setup_vault_dev_container};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_setup_pki() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault2::vault::setup_pki(&vault_url, "root", domain, ttl, false, None, None).await?;

    println!("CA Certificate:\n{}", cert);
    println!("PKI role name: {}", role_name);

    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert_eq!(role_name, domain.replace('.', "-"));

    Ok(())
}

#[tokio::test]
async fn test_setup_pki_same_vault_intermediate() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert_chain, role_name) =
        merka_vault2::vault::setup_pki(&vault_url, "root", domain, ttl, true, None, None).await?;

    println!("CA Certificate Chain:\n{}", cert_chain);
    println!("PKI role name: {}", role_name);

    assert!(cert_chain.contains("BEGIN CERTIFICATE"));
    let cert_count = cert_chain.matches("BEGIN CERTIFICATE").count();
    assert!(cert_count >= 2);
    assert_eq!(role_name, domain.replace('.', "-"));

    Ok(())
}

#[tokio::test]
async fn test_setup_pki_secondary_vault_intermediate() -> Result<(), Box<dyn std::error::Error>> {
    // Start two Vault containers using the non‑dev setup.
    let root_vault_container = setup_vault_container().await;
    let int_vault_container = setup_vault_container().await;
    let root_host = root_vault_container.get_host().await.unwrap();
    let root_port = root_vault_container.get_host_port_ipv4(8200).await.unwrap();
    let int_host = int_vault_container.get_host().await.unwrap();
    let int_port = int_vault_container.get_host_port_ipv4(8200).await.unwrap();
    let root_url = format!("http://{}:{}", root_host, root_port);
    let int_url = format!("http://{}:{}", int_host, int_port);

    // Allow containers to start up.
    sleep(Duration::from_secs(3)).await;

    // Initialize and unseal the root Vault.
    let init_res = merka_vault2::vault::init_vault(&root_url, 5, 3).await?;
    assert!(!init_res.root_token.is_empty());
    merka_vault2::vault::unseal_vault(&root_url, &init_res.keys).await?;
    let root_token = init_res.root_token;

    // Initialize and unseal the intermediate Vault.
    let int_init_res = merka_vault2::vault::init_vault(&int_url, 5, 3).await?;
    assert!(!int_init_res.root_token.is_empty());
    merka_vault2::vault::unseal_vault(&int_url, &int_init_res.keys).await?;
    let int_root_token = int_init_res.root_token; // Use this token for intermediate Vault operations

    let domain = "example.com";
    let ttl = "8760h";
    let (cert_chain, role_name) = merka_vault2::vault::setup_pki_intermediate(
        &root_url,
        &root_token,
        &int_url,
        &int_root_token,
        domain,
        ttl,
    )
    .await?;

    println!("CA Certificate Chain:\n{}", cert_chain);
    println!("PKI role name: {}", role_name);

    assert!(cert_chain.contains("BEGIN CERTIFICATE"));
    let cert_count = cert_chain.matches("BEGIN CERTIFICATE").count();
    assert!(cert_count >= 2);
    assert_eq!(role_name, format!("{}-int", domain.replace('.', "-")));

    Ok(())
}

#[tokio::test]
async fn test_setup_approle() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let role_name = "test-role";
    let policies = vec!["default".to_string()];
    let creds =
        merka_vault2::vault::setup_approle(&vault_url, "root", role_name, &policies).await?;

    println!(
        "AppRole credentials: role_id: {}, secret_id: {}",
        creds.role_id, creds.secret_id
    );
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_vault_init_and_unseal() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    assert!(merka_vault2::vault::init_vault(&vault_url, 1, 1)
        .await
        .is_err());

    Ok(())
}

#[tokio::test]
async fn test_pki_and_auth_setup() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault2::vault::setup_pki(&vault_url, "root", domain, ttl, false, None, None).await?;
    assert!(cert.contains("BEGIN CERTIFICATE"));
    println!(
        "PKI setup complete: role '{}' for domain {}, CA cert length {}",
        role_name,
        domain,
        cert.len()
    );

    let role = "test-role";
    let policies = vec!["default".to_string()];
    let creds = merka_vault2::vault::setup_approle(&vault_url, "root", role, &policies).await?;
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());
    println!(
        "AppRole '{}' -> role_id={}, secret_id={}",
        role, creds.role_id, creds.secret_id
    );

    let k8s_role = "test-k8s-role";
    let sa_name = "vault-auth";
    let ns = "default";
    let k8s_host = "https://kubernetes.default.svc";
    let k8s_ca = "---BEGIN CERTIFICATE---\nMIIF...==\n-----END CERTIFICATE-----";
    let result = merka_vault2::vault::setup_kubernetes_auth(
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
    assert!(result.is_ok() || matches!(result, Err(merka_vault2::vault::VaultError::Api(_))));
    Ok(())
}

#[tokio::test]
async fn test_full_vault_setup() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container().await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let init_res = merka_vault2::vault::init_vault(&vault_url, 1, 1).await?;
    assert!(!init_res.root_token.is_empty());
    merka_vault2::vault::unseal_vault(&vault_url, &init_res.keys).await?;
    let root_token = init_res.root_token;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault2::vault::setup_pki(&vault_url, &root_token, domain, ttl, false, None, None)
            .await?;
    assert!(cert.contains("BEGIN CERTIFICATE"));
    println!(
        "PKI setup complete: role '{}' for domain {}, CA cert length {}",
        role_name,
        domain,
        cert.len()
    );

    let role = "test-role";
    let policies = vec!["default".to_string()];
    let creds =
        merka_vault2::vault::setup_approle(&vault_url, &root_token, role, &policies).await?;
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());
    println!(
        "AppRole '{}' -> role_id={}, secret_id={}",
        role, creds.role_id, creds.secret_id
    );

    let k8s_role = "test-k8s-role";
    let sa_name = "vault-auth";
    let ns = "default";
    let k8s_host = "https://kubernetes.default.svc";
    let k8s_ca = "---BEGIN CERTIFICATE---\nMIIF...==\n-----END CERTIFICATE-----";
    let result = merka_vault2::vault::setup_kubernetes_auth(
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
    assert!(result.is_ok() || matches!(result, Err(merka_vault2::vault::VaultError::Api(_))));
    Ok(())
}
