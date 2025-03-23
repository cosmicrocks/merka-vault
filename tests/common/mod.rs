//! This module provides common utilities for setting up Vault and Caddy containers
//! for integration testing.

use std::sync::{Mutex, OnceLock};
use testcontainers::{
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

// Global storage for test name access
static CURRENT_TEST_NAME: OnceLock<String> = OnceLock::new();
// Track if we've initialized logging
static INIT_DONE: OnceLock<Mutex<bool>> = OnceLock::new();

/// Set up logging for tests with current test name in each log line
pub fn init_logging() {
    // Ensure we only initialize once
    let init_done = INIT_DONE.get_or_init(|| Mutex::new(false));
    let mut initialized = init_done.lock().unwrap();
    if *initialized {
        // Already initialized
        return;
    }

    // Get the current test name from the current thread
    let thread_name = std::thread::current()
        .name()
        .unwrap_or("unknown")
        .to_string();
    let test_name = thread_name
        .split("::")
        .last()
        .unwrap_or("unknown")
        .to_string();

    // Store in global for potential use elsewhere
    let _ = CURRENT_TEST_NAME.set(test_name.clone());

    // Custom format for the fmt layer that includes the test name
    let format = fmt::format()
        .with_level(true)
        .with_target(false)
        .with_ansi(true)
        .with_file(true)
        .with_line_number(true)
        .compact();

    // Create and initialize the subscriber with test name prefix
    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_test_writer()
        .with_timer(fmt::time::uptime())
        .event_format(format)
        .finish();

    // Initialize subscriber
    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("Warning: Failed to set global default subscriber: {}", e);
    } else {
        *initialized = true;
    }

    // Log the test name as the first message
    info!("[TEST: {}] Test started", test_name);
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
