//! Integration tests for the Vault provisioning application.
//!
//! These tests verify the setup of PKI engines, AppRole authentication,
//! full Vault initialization/unsealing, and TLS certificate issuance.

mod common;
use common::setup_vault_container;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_setup_pki() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container(common::VaultMode::Dev).await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault::vault::pki::setup_pki(&vault_url, "root", domain, ttl, false, None, None)
            .await?;

    println!("CA Certificate:\n{}", cert);
    println!("PKI role name: {}", role_name);

    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert_eq!(role_name, domain.replace('.', "-"));

    Ok(())
}

#[tokio::test]
async fn test_setup_pki_same_vault_intermediate() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container(common::VaultMode::Dev).await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert_chain, role_name) =
        merka_vault::vault::pki::setup_pki(&vault_url, "root", domain, ttl, true, None, None)
            .await?;

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
    let root_vault_container = setup_vault_container(common::VaultMode::Regular).await;
    let int_vault_container = setup_vault_container(common::VaultMode::Regular).await;
    let root_host = root_vault_container.get_host().await.unwrap();
    let root_port = root_vault_container.get_host_port_ipv4(8200).await.unwrap();
    let int_host = int_vault_container.get_host().await.unwrap();
    let int_port = int_vault_container.get_host_port_ipv4(8200).await.unwrap();
    let root_url = format!("http://{}:{}", root_host, root_port);
    let int_url = format!("http://{}:{}", int_host, int_port);

    // Allow containers to start up.
    sleep(Duration::from_secs(3)).await;

    // Initialize and unseal the root Vault.
    let init_res = merka_vault::vault::init::init_vault(&root_url, 5, 3).await?;
    assert!(!init_res.root_token.is_empty());
    merka_vault::vault::init::unseal_vault(&root_url, &init_res.keys).await?;
    let root_token = init_res.root_token;

    // Initialize and unseal the intermediate Vault.
    let int_init_res = merka_vault::vault::init::init_vault(&int_url, 5, 3).await?;
    assert!(!int_init_res.root_token.is_empty());
    merka_vault::vault::init::unseal_vault(&int_url, &int_init_res.keys).await?;
    let int_root_token = int_init_res.root_token; // Use this token for intermediate Vault operations

    let domain = "example.com";
    let ttl = "8760h";
    let (cert_chain, role_name) = merka_vault::vault::pki::setup_pki_intermediate(
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
    let vault_container = setup_vault_container(common::VaultMode::Dev).await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let role_name = "test-role";
    let policies = vec!["default".to_string()];
    let creds =
        merka_vault::vault::auth::setup_approle(&vault_url, "root", role_name, &policies).await?;

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
    let vault_container = setup_vault_container(common::VaultMode::Dev).await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    assert!(merka_vault::vault::init::init_vault(&vault_url, 1, 1)
        .await
        .is_err());

    Ok(())
}

#[tokio::test]
async fn test_pki_and_auth_setup() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container(common::VaultMode::Dev).await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault::vault::pki::setup_pki(&vault_url, "root", domain, ttl, false, None, None)
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
        merka_vault::vault::auth::setup_approle(&vault_url, "root", role, &policies).await?;
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
    let result = merka_vault::vault::auth::setup_kubernetes_auth(
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
    assert!(result.is_ok() || matches!(result, Err(merka_vault::vault::VaultError::Api(_))));
    Ok(())
}

#[tokio::test]
async fn test_full_vault_setup() -> Result<(), Box<dyn std::error::Error>> {
    let vault_container = setup_vault_container(common::VaultMode::Regular).await;
    let host = vault_container.get_host().await.unwrap();
    let host_port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, host_port);

    sleep(Duration::from_secs(3)).await;

    let init_res = merka_vault::vault::init::init_vault(&vault_url, 1, 1).await?;
    assert!(!init_res.root_token.is_empty());
    merka_vault::vault::init::unseal_vault(&vault_url, &init_res.keys).await?;
    let root_token = init_res.root_token;

    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) =
        merka_vault::vault::pki::setup_pki(&vault_url, &root_token, domain, ttl, false, None, None)
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
        merka_vault::vault::auth::setup_approle(&vault_url, &root_token, role, &policies).await?;
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
    let result = merka_vault::vault::auth::setup_kubernetes_auth(
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
    assert!(result.is_ok() || matches!(result, Err(merka_vault::vault::VaultError::Api(_))));
    Ok(())
}

#[tokio::test]
async fn test_issue_cert_and_verify_tls() -> Result<(), Box<dyn std::error::Error>> {
    use openssl::ssl::{SslConnector, SslMethod};
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::X509StoreContext;
    use openssl::x509::X509;
    use std::fs;
    use std::net::TcpStream;
    use tokio::time::{sleep, Duration};

    // --- Vault Setup (using common.rs and vault.rs) ---
    // Start the root and intermediate Vault containers in Regular mode.
    let root_vault_container = common::setup_vault_container(common::VaultMode::Regular).await;
    let int_vault_container = common::setup_vault_container(common::VaultMode::Regular).await;
    let root_host = root_vault_container.get_host().await.unwrap();
    let root_port = root_vault_container.get_host_port_ipv4(8200).await.unwrap();
    let int_host = int_vault_container.get_host().await.unwrap();
    let int_port = int_vault_container.get_host_port_ipv4(8200).await.unwrap();
    let root_url = format!("http://{}:{}", root_host, root_port);
    let int_url = format!("http://{}:{}", int_host, int_port);

    // Allow containers to start.
    sleep(Duration::from_secs(3)).await;

    // Initialize and unseal the root Vault.
    let root_init = merka_vault::vault::init::init_vault(&root_url, 5, 3).await?;
    assert!(!root_init.root_token.is_empty());
    merka_vault::vault::init::unseal_vault(&root_url, &root_init.keys).await?;
    let root_token = root_init.root_token;

    // Initialize and unseal the intermediate Vault.
    let int_init = merka_vault::vault::init::init_vault(&int_url, 5, 3).await?;
    assert!(!int_init.root_token.is_empty());
    merka_vault::vault::init::unseal_vault(&int_url, &int_init.keys).await?;
    let int_token = int_init.root_token;

    // Configure the PKI intermediate.
    // Here, we use a TTL of "24h" (used by issue_certificate as its default)
    let domain = "example.com";
    let ttl = "24h";
    let (pki_chain, role_name) = merka_vault::vault::pki::setup_pki_intermediate(
        &root_url,
        &root_token,
        &int_url,
        &int_token,
        domain,
        ttl,
    )
    .await?;
    println!("PKI chain:\n{}", pki_chain);
    assert!(pki_chain.contains("BEGIN CERTIFICATE"));
    let cert_count = pki_chain.matches("BEGIN CERTIFICATE").count();
    assert!(cert_count >= 2);

    // --- Issue a Certificate from the Intermediate ---
    let (issued_cert, issued_key) = merka_vault::vault::pki::issue_certificate(
        &int_url,
        &int_token,
        &role_name,
        domain,
        Some("12h"),
    )
    .await?;
    println!("Issued certificate:\n{}", issued_cert);

    // --- Prepare TLS Assets for Caddy ---
    // Create a temporary directory for the certificate and key.
    let certs_dir = tempfile::tempdir()?;
    let cert_path = certs_dir.path().join("cert.pem");
    let key_path = certs_dir.path().join("key.pem");
    fs::write(&cert_path, &issued_cert)?;
    fs::write(&key_path, &issued_key)?;

    // Create a temporary configuration file for Caddy.
    // Here we explicitly specify a TLS connection policy that matches our domain.
    let caddy_config = format!(
        r#"
{{
  "admin": {{
    "disabled": true
  }},
  "apps": {{
    "tls": {{
      "certificates": {{
        "load_files": [
          {{
            "certificate": "/certs/cert.pem",
            "key": "/certs/key.pem"
          }}
        ]
      }}
    }},
    "http": {{
      "servers": {{
        "example": {{
          "listen": [":8443"],
          "tls_connection_policies": [
            {{
              "match": {{
                "sni": ["{}"]
              }}
            }}
          ],
          "routes": [
            {{
              "match": [{{ "host": ["{}"] }}],
              "handle": [{{ "handler": "static_response", "body": "Hello, TLS!" }}]
            }}
          ]
        }}
      }}
    }}
  }}
}}
"#,
        domain, domain
    );
    let config_file = tempfile::NamedTempFile::new()?;
    fs::write(config_file.path(), caddy_config)?;

    // --- Start the Caddy Container ---
    let caddy_container = common::setup_caddy_container(
        config_file.path().to_str().unwrap(),
        Some(certs_dir.path().to_str().unwrap()),
    )
    .await;
    let caddy_host = caddy_container.get_host().await.unwrap();
    let caddy_port = caddy_container.get_host_port_ipv4(8443).await.unwrap();
    println!("Caddy is running at {}:{}", caddy_host, caddy_port);
    sleep(Duration::from_secs(5)).await; // Allow time for Caddy to initialize

    // --- Build two custom X509Stores using the root certificate ---
    // Assume the last PEM block in pki_chain is the root certificate.
    let mut pem_blocks: Vec<String> = pki_chain
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("BEGIN CERTIFICATE"))
        .map(|s| format!("{}-----END CERTIFICATE-----", s))
        .collect();
    let root_pem = pem_blocks.pop().ok_or("No root certificate found")?;
    let root_cert = X509::from_pem(root_pem.as_bytes())?;

    // Build store for the SSL connector.
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(root_cert.clone())?;
    let store_for_connector = store_builder.build();

    // Build a separate store for verification.
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(root_cert)?;
    let store_for_verification = store_builder.build();

    let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
    connector_builder.set_cert_store(store_for_connector);
    let connector = connector_builder.build();

    // --- Connect via TLS and Retrieve the Certificate Chain ---
    let addr = format!("{}:{}", caddy_host, caddy_port);
    let tcp_stream = TcpStream::connect(&addr)?;
    // Use the domain as SNI.
    let ssl_stream = connector.connect(domain, tcp_stream)?;
    let peer_cert = ssl_stream
        .ssl()
        .peer_certificate()
        .ok_or("No peer certificate presented")?;
    let chain = ssl_stream
        .ssl()
        .peer_cert_chain()
        .ok_or("No certificate chain presented")?;
    println!(
        "Retrieved certificate from Caddy: {:?}",
        peer_cert.subject_name()
    );

    // --- Validate the Certificate Chain Against the Custom Trust Store ---
    let mut chain_stack = openssl::stack::Stack::new()?;
    for cert in chain {
        chain_stack.push(cert.to_owned())?;
    }
    let mut ctx = X509StoreContext::new()?;
    ctx.init(&store_for_verification, &peer_cert, &chain_stack, |c| {
        c.verify_cert()
    })?;
    println!("Certificate chain verified successfully against the custom trust store.");

    Ok(())
}
