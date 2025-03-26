use std::time::Duration;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
use tracing::{debug, info};

/// Indicates the mode in which to run the Vault container.
#[derive(Debug, Clone)]
pub enum VaultMode {
    Regular,
    Dev,
    #[allow(dead_code)]
    AutoUnseal {
        transit_unseal_url: String,
        token: String,
        key_name: String,
    },
}

/// Sets up a Vault container for testing.
pub async fn setup_vault_container(mode: VaultMode) -> ContainerAsync<GenericImage> {
    info!("Setting up Vault container in {:?} mode", mode);

    let container_request = match mode {
        VaultMode::Dev => GenericImage::new("hashicorp/vault", "1.13.3")
            .with_exposed_port(8200.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .with_cmd(vec!["server", "-dev", "-dev-root-token-id=root"]),
        VaultMode::Regular => {
            let vault_local_config = r#"
            {"storage": {"file": {"path": "/vault/file"}},
             "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}],
             "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}
            "#;
            GenericImage::new("hashicorp/vault", "1.13.3")
                .with_exposed_port(8200.tcp())
                .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
                .with_env_var("VAULT_LOCAL_CONFIG", vault_local_config)
                .with_cmd(vec!["server"])
                .with_cap_add("IPC_LOCK")
        }
        VaultMode::AutoUnseal {
            ref transit_unseal_url,
            ref token,
            ref key_name,
        } => GenericImage::new("hashicorp/vault", "1.13.3")
            .with_exposed_port(8200.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
            .with_env_var("VAULT_ADDR", transit_unseal_url)
            .with_env_var("VAULT_TOKEN", token)
            .with_env_var("VAULT_TRANSIT_KEY", key_name)
            .with_env_var("VAULT_UNSEAL_MECHANISM", "transit"),
    };

    // Start the container asynchronously
    let container = container_request
        .start()
        .await
        .expect("Failed to start container");
    info!("Vault container started");
    container
}

/// Wait for Vault to be ready
pub async fn wait_for_vault_ready(
    vault_addr: &str,
    max_retries: usize,
    retry_delay_ms: u64,
) -> Result<(), String> {
    use reqwest::Client;
    use tokio::time::sleep;

    let client = Client::new();
    let health_url = format!("{}/v1/sys/health", vault_addr);

    info!("Waiting for Vault to be available at: {}", vault_addr);

    for attempt in 1..=max_retries {
        match client.get(&health_url).send().await {
            Ok(response) => {
                // Check response status
                let status = response.status().as_u16();
                match status {
                    200 => {
                        info!(
                            "Vault ready (initialized, unsealed, active) after {} attempts",
                            attempt
                        );
                        return Ok(());
                    }
                    429 => {
                        info!("Vault ready (unsealed, standby) after {} attempts", attempt);
                        return Ok(());
                    }
                    // Other status codes indicate Vault is not yet ready
                    _ => {
                        debug!("Vault not ready yet (status: {}), retrying...", status);
                    }
                }
            }
            Err(e) => {
                debug!("Connection to Vault failed (attempt {}): {}", attempt, e);
            }
        }

        sleep(Duration::from_millis(retry_delay_ms)).await;
    }

    Err(format!("Vault not ready after {} attempts", max_retries))
}

/// Sets up a Caddy container for testing TLS certificates
#[allow(dead_code)]
pub async fn setup_caddy_container(
    config_path: &str,
    certs_dir: Option<&str>,
) -> ContainerAsync<GenericImage> {
    use testcontainers::core::Mount;

    let mut image = GenericImage::new("caddy", "2.7.4")
        .with_exposed_port(8443.tcp())
        .with_wait_for(WaitFor::message_on_stdout("serving initial configuration"))
        .with_mount(Mount::bind_mount(
            config_path.to_string(),
            "/etc/caddy/Caddyfile".to_string(),
        ));

    // Add certs directory if provided
    if let Some(dir) = certs_dir {
        image = image.with_mount(Mount::bind_mount(dir.to_string(), "/certs".to_string()));
    }

    let container = image
        .start()
        .await
        .expect("Failed to start Caddy container");
    info!("Caddy container started");
    container
}
