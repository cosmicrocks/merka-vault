use std::time::Duration;
use testcontainers::{core::IntoContainerPort, GenericImage, ImageExt};
use tokio::time::sleep;

#[tokio::test]
async fn test_setup_pki_with_testcontainers() -> Result<(), Box<dyn std::error::Error>> {
    // Create a Docker client using testcontainers

    // Define the Vault image to run in dev mode.
    // We use the image "hashicorp/vault:1.18.4" with environment variable and command
    // settings that auto‑initialize and unseal Vault with a fixed root token "root".
    // Note that we expose container port 8200 (TCP) and wait for Vault to log
    // a readiness message.
    let vault_image = GenericImage::new("hashicorp/vault", "1.18.4")
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .with_cmd(vec!["server", "-dev", "-dev-root-token-id=root"])
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"));

    // Run the container. When the container handle goes out of scope it will be automatically removed.
    let container = docker.run(vault_image);

    // Determine the host port mapped to container port 8200.
    let port = container.get_host_port_ipv4(8200);
    let vault_addr = format!("http://127.0.0.1:{}", port);

    // Wait briefly to ensure Vault is fully ready.
    sleep(Duration::from_secs(3)).await;

    // Now call the PKI setup function from your library.
    let domain = "example.com";
    let ttl = "8760h";
    let (cert, role_name) = merka_vault::vault::setup_pki(&vault_addr, "root", domain, ttl).await?;

    println!("CA Certificate:\n{}", cert);
    println!("PKI role name: {}", role_name);

    // Verify the returned certificate contains a PEM header.
    assert!(cert.contains("BEGIN CERTIFICATE"));
    // The role name is expected to be the domain with dots replaced by hyphens.
    assert_eq!(role_name, domain.replace('.', "-"));

    Ok(())
}

#[tokio::test]
async fn test_setup_approle_with_testcontainers() -> Result<(), Box<dyn std::error::Error>> {
    // Create a Docker client.
    let docker = Cli::default();

    // Define and run Vault container in dev mode.
    let vault_image = GenericImage::new("hashicorp/vault", "1.18.4")
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .with_cmd(vec!["server", "-dev", "-dev-root-token-id=root"])
        .with_exposed_port(8200_u16.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"));
    let container = docker.run(vault_image);
    let port = container.get_host_port_ipv4(8200);
    let vault_addr = format!("http://127.0.0.1:{}", port);

    sleep(Duration::from_secs(3)).await;

    // Now test the AppRole setup.
    let role_name = "test-role";
    let policies = vec!["default".to_string()];
    let creds =
        merka_vault::vault::setup_approle(&vault_addr, "root", role_name, &policies).await?;

    println!(
        "AppRole credentials: role_id: {}, secret_id: {}",
        creds.role_id, creds.secret_id
    );

    // Verify that non-empty RoleID and SecretID are returned.
    assert!(!creds.role_id.is_empty());
    assert!(!creds.secret_id.is_empty());

    Ok(())
}
