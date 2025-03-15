//! This module provides common utilities for setting up Vault and Caddy containers
//! for integration testing.

use testcontainers::{
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
use tracing::info;

/// Set up logging for tests
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer() // This ensures output goes to both stdout and test output
        .try_init();
}

/// Indicates the mode in which to run the Vault container.
/// Use `Dev` for development mode with relaxed security and `Regular` for a production-like configuration.
#[allow(dead_code)]
pub enum VaultMode {
    // Regular mode is closer to production usage.
    Regular,
    Dev,
    // Auto-unseal mode pre-configures Vault with transit auto-unseal
    AutoUnseal {
        transit_unseal_url: String, // renamed from unsealer_url
        token: String,
        key_name: String,
    },
}

// Helper function to create a base Vault container
fn create_base_vault_container() -> testcontainers::core::ContainerRequest<GenericImage> {
    GenericImage::new("hashicorp/vault", "1.18.4")
        .with_exposed_port(8200.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
        .with_network("bridge")
}

pub async fn setup_vault_container(mode: VaultMode) -> ContainerAsync<GenericImage> {
    // updated return type
    match mode {
        VaultMode::Dev => create_base_vault_container()
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .with_cmd(vec!["server", "-dev", "-dev-root-token-id=root"])
            .start()
            .await
            .unwrap(),
        VaultMode::Regular => {
            let vault_local_config = r#"
            {"storage": {"file": {"path": "/vault/file"}},
             "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}],
             "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}
            "#;
            create_base_vault_container()
                .with_env_var("VAULT_LOCAL_CONFIG", vault_local_config)
                .with_cmd(vec!["server"])
                .with_cap_add("IPC_LOCK")
                .start()
                .await
                .unwrap()
        }
        VaultMode::AutoUnseal {
            transit_unseal_url,
            token,
            key_name,
        } => {
            let auto_unseal_config = format!(
                r#"
            {{
                "storage": {{"file": {{"path": "/vault/file"}}}},
                "listener": [{{"tcp": {{ "address": "0.0.0.0:8200", "tls_disable": true}}}}],
                "seal": {{
                    "transit": {{
                        "address": "{}",
                        "key_name": "{}",
                        "mount_path": "transit/",
                        "tls_skip_verify": true
                    }}
                }},
                "default_lease_ttl": "168h",
                "max_lease_ttl": "720h",
                "ui": true
            }}
            "#,
                transit_unseal_url, key_name
            );

            info!(
                "Starting Vault with auto-unseal configuration connected to: {}",
                transit_unseal_url
            );

            create_base_vault_container()
                .with_env_var("VAULT_LOCAL_CONFIG", auto_unseal_config)
                .with_env_var("VAULT_TOKEN", token)
                .with_cmd(vec!["server"])
                .with_cap_add("IPC_LOCK")
                .start()
                .await
                .unwrap()
        }
    }
}

/// Sets up a Caddy container using the provided configuration file.
/// If `certs_dir` is provided, it sets up the container with TLS.
#[allow(dead_code)]
pub async fn setup_caddy_container(
    config_path: &str,
    certs_dir: Option<&str>,
) -> ContainerAsync<GenericImage> {
    let mut image = GenericImage::new("caddy", "2.9.1")
        .with_exposed_port(if certs_dir.is_some() { 8443 } else { 2015 }.tcp())
        .with_mount(Mount::bind_mount(
            config_path.to_string(),
            "/etc/caddy/config.json".to_string(),
        ))
        .with_cmd(vec!["caddy", "run", "--config", "/etc/caddy/config.json"]);

    if let Some(certs) = certs_dir {
        image = image.with_mount(Mount::bind_mount(certs.to_string(), "/certs".to_string()));
    }

    image.start().await.unwrap()
}
