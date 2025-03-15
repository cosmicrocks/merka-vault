use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

// Import vault functions from our modules.
use crate::vault::{
    autounseal,
    common::check_vault_status,
    init::{
        init_vault, initialize_vault_infrastructure, unseal_root_vault, InitOptions, InitResult,
    },
    pki,
};

#[derive(Parser)]
#[command(
    name = "merka-vault",
    about = "Vault provisioning CLI (supports init, unseal, pki setup and autounseal)",
    version = "0.1.0"
)]
pub struct Cli {
    /// Root Vault server address.
    #[arg(long, default_value = "http://127.0.0.1:8200", env = "ROOT_VAULT_ADDR")]
    pub vault_addr: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Unseal Vault.
    Unseal {
        /// Provide one or more unseal keys.
        #[arg(long, value_name = "UNSEAL_KEY")]
        keys: Vec<String>,
        /// Optionally read keys from a file.
        #[arg(long)]
        keys_file: Option<String>,
    },
    /// Check Vault status.
    Status {
        /// Specify the Vault address to check (defaults to root vault)
        #[arg(long)]
        vault_addr: Option<String>,
    },
    /// Fully automate multi‑tier Vault setup with auto‑unseal and PKI.
    ///
    /// This command performs these steps:
    /// 1. Initializes (if needed) and unseals the root Vault.
    /// 2. Sets up the transit engine on the root Vault.
    /// 3. Generates a wrapped token, unwraps it, and restarts the sub‑Vault container with the token injected.
    /// 4. Waits for the sub‑Vault to unseal.
    /// 5. Proceeds with PKI setup on both Vaults.
    Setup {
        /// Root Vault address.
        #[arg(long, default_value = "http://127.0.0.1:8200", env = "ROOT_VAULT_ADDR")]
        root_addr: String,
        /// Sub Vault address.
        #[arg(long, default_value = "http://127.0.0.1:8202", env = "SUB_VAULT_ADDR")]
        sub_addr: String,
        /// Secret shares for initialization.
        #[arg(long, default_value_t = 1)]
        secret_shares: u8,
        /// Secret threshold for initialization.
        #[arg(long, default_value_t = 1)]
        secret_threshold: u8,
        /// Domain name for PKI setup.
        #[arg(long, default_value = "example.com")]
        domain: String,
        /// TTL for certificates.
        #[arg(long, default_value = "8760h")]
        ttl: String,
        /// Name for auto‑unseal key.
        #[arg(long, default_value = "autounseal-key")]
        key_name: String,
        /// Optional output file to save credentials.
        #[arg(long)]
        output_file: Option<String>,
        /// Optional root token if the root Vault is already initialized.
        #[arg(long)]
        root_token: Option<String>,
    },
}

/// Wait for a Vault at `addr` to become unsealed within `timeout`.
async fn wait_for_vault_unseal(addr: &str, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        match check_vault_status(addr).await {
            Ok(status) if status.initialized && !status.sealed => {
                info!("Vault at {} is unsealed.", addr);
                return Ok(());
            }
            Ok(status) => {
                info!(
                    "Waiting for Vault at {} (initialized: {}, sealed: {})",
                    addr, status.initialized, status.sealed
                );
            }
            Err(e) => warn!("Error checking Vault status at {}: {}", addr, e),
        }
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Timed out waiting for Vault at {} to unseal",
                addr
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Wait for a Vault at `addr` to become available within `timeout`.
async fn wait_for_vault_availability(addr: &str, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    info!("Waiting for Vault at {} to become available...", addr);
    loop {
        let response = reqwest::get(format!("{}/v1/sys/health", addr)).await;

        match response {
            Ok(response) => {
                // Try to parse the response body as text
                match response.text().await {
                    Ok(body) => {
                        if body.contains("initialized") {
                            info!("Vault at {} is available (responding to API calls).", addr);
                            return Ok(());
                        }
                        info!("Vault responded but with unexpected content, continuing to wait...");
                    }
                    Err(_) => {
                        info!("Vault responded but couldn't read body, continuing to wait...");
                    }
                }
            }
            Err(_) => {
                info!("Waiting for Vault at {} to become available...", addr);
            }
        }

        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Timed out waiting for Vault at {} to become available",
                addr
            ));
        }
        sleep(Duration::from_secs(1)).await;
    }
}

/// Wait for the sub Vault to be unsealed.
async fn wait_for_sub_vault(addr: &str, timeout: Duration) -> Result<()> {
    wait_for_vault_unseal(addr, timeout).await
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Unseal { keys, keys_file } => {
            info!("Unsealing Vault at {}", cli.vault_addr);
            let mut unseal_keys = Vec::new();
            if let Some(file) = keys_file {
                let contents = fs::read_to_string(file)?;
                for line in contents.lines() {
                    let line = line.trim();
                    if !line.is_empty() {
                        unseal_keys.push(line.to_string());
                    }
                }
            }
            unseal_keys.extend(keys);
            if unseal_keys.is_empty() {
                return Err(anyhow::anyhow!("No unseal keys provided"));
            }
            let result = unseal_root_vault(&cli.vault_addr, unseal_keys).await?;
            info!("Unseal result: sealed = {}", result.sealed);
            info!("Progress: {}/{}", result.progress, result.threshold);
        }
        Commands::Status { vault_addr } => {
            let addr = vault_addr.unwrap_or_else(|| cli.vault_addr.clone());
            info!("Checking status of Vault at {}", addr);
            match check_vault_status(&addr).await {
                Ok(status) => {
                    info!(
                        "Vault Status: Initialized: {}, Sealed: {}, Standby: {}",
                        status.initialized, status.sealed, status.standby
                    );
                    if status.initialized && !status.sealed {
                        info!("Active Node: Yes");
                    }
                    if !status.initialized {
                        info!("Vault is not initialized. Run the setup command to initialize and configure the vault.");
                    } else if status.sealed {
                        info!("Vault is sealed. Run the unseal command to unseal.");
                    }
                }
                Err(e) => {
                    error!("Error checking Vault status: {}", e);
                    if e.to_string().contains("connect") || e.to_string().contains("connection") {
                        error!("Connection error: Ensure Vault is running at {}", addr);
                    }
                    return Err(anyhow::anyhow!("Failed to check Vault status: {}", e));
                }
            }
        }
        Commands::Setup {
            root_addr,
            sub_addr,
            secret_shares,
            secret_threshold,
            domain,
            ttl,
            key_name,
            output_file,
            root_token: maybe_root_token,
        } => {
            info!("Starting multi‑tier Vault infrastructure setup:");
            info!("  Root Vault: {}", root_addr);
            info!("  Sub Vault: {}", sub_addr);

            // Step 1: Initialize (if needed) and unseal the root Vault.
            let root_status = check_vault_status(&root_addr).await?;
            let root_init: InitResult;
            if !root_status.initialized {
                info!("Root Vault is not initialized.");
                let init_opts = InitOptions {
                    secret_shares,
                    secret_threshold,
                };
                if root_status.type_field == "shamir" {
                    info!("Vault seal type is 'shamir'. Using secret_shares/secret_threshold.");
                    root_init = initialize_vault_infrastructure(&root_addr, init_opts).await?;
                } else {
                    info!(
                        "Vault seal type is '{}'. Using recovery parameters.",
                        root_status.type_field
                    );
                    root_init = init_vault(
                        &root_addr,
                        secret_shares,
                        secret_threshold,
                        Some(secret_shares),
                        Some(secret_threshold),
                    )
                    .await?;
                }
                info!(
                    "Root Vault initialized with token: {}",
                    root_init.root_token
                );
                info!("Unsealing root Vault...");
                let unseal_result = unseal_root_vault(&root_addr, root_init.keys.clone()).await?;
                info!(
                    "Root Vault unsealed: sealed = {}, progress = {}/{}",
                    unseal_result.sealed, unseal_result.progress, unseal_result.threshold
                );
            } else {
                info!("Root Vault is already initialized.");
                if let Some(rt) = maybe_root_token {
                    info!("Using provided root token.");
                    root_init = InitResult {
                        keys: vec![],
                        keys_base64: None,
                        recovery_keys: None,
                        recovery_keys_base64: None,
                        root_token: rt,
                    };
                } else {
                    return Err(anyhow::anyhow!(
                        "Vault at {} is already initialized. Please provide the root token using --root-token.",
                        root_addr
                    ));
                }
            }

            // Step 2: Wait for the root Vault to be unsealed.
            info!("Waiting for root Vault to be unsealed...");
            wait_for_vault_unseal(&root_addr, Duration::from_secs(60)).await?;

            // Step 3: Configure Transit engine on the root Vault.
            info!("Setting up transit auto‑unseal on root Vault...");
            autounseal::setup_transit_autounseal(&root_addr, &root_init.root_token, &key_name)
                .await?;
            info!("Transit auto‑unseal setup completed on root Vault.");

            // Step 4: Generate a wrapped token and unwrap it.
            info!("Generating wrapped transit token...");
            let wrap_ttl = "300s";
            let wrapped_token = crate::vault::transit::generate_wrapped_transit_token(
                &root_addr,
                &root_init.root_token,
                "autounseal",
                wrap_ttl,
            )
            .await?;
            info!("Wrapped token obtained.");
            let unwrapped_token = autounseal::unwrap_token(&root_addr, &wrapped_token).await?;
            info!("Unwrapped token obtained.");

            // Step 5: Restart the sub Vault container with the new VAULT_TOKEN.
            info!("Restarting sub Vault container with updated VAULT_TOKEN...");
            let output = Command::new("docker-compose")
                .env("VAULT_TOKEN", unwrapped_token.clone())
                .args(&["up", "-d", "--force-recreate", "sub-vault"])
                .output()?;
            if !output.status.success() {
                warn!(
                    "Failed to restart sub‑vault container: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                info!("Sub‑vault container restarted successfully.");
            }

            // Wait for the sub-vault to be available before initialization
            info!("Waiting for sub-vault to become available...");
            wait_for_vault_availability(&sub_addr, Duration::from_secs(30)).await?;

            // Step 6: Initialize the sub Vault with auto‑unseal.
            info!("Initializing sub Vault with auto‑unseal...");
            let sub_init = autounseal::init_with_autounseal(&sub_addr).await?;
            info!(
                "Sub Vault auto‑initialized with token: {}",
                sub_init.root_token
            );

            // Step 7: Wait for the sub Vault to be unsealed.
            info!("Waiting for sub Vault to be unsealed...");
            wait_for_sub_vault(&sub_addr, Duration::from_secs(60)).await?;

            // Step 8: Set up PKI on the root Vault.
            info!("Setting up root PKI on root Vault...");
            let (root_cert, root_role) = pki::setup_pki(
                &root_addr,
                &root_init.root_token,
                &domain,
                &ttl,
                false,
                None,
                None,
            )
            .await?;
            info!("Root PKI setup complete. PKI Role: {}", root_role);

            // Step 9: Set up intermediate PKI on the sub Vault.
            info!("Setting up intermediate PKI on sub Vault...");
            let (int_cert, int_role) = pki::setup_pki_intermediate(
                &root_addr,
                &root_init.root_token,
                &sub_addr,
                &sub_init.root_token,
                &domain,
                &ttl,
            )
            .await?;
            info!(
                "Intermediate PKI setup complete. Intermediate PKI Role: {}",
                int_role
            );

            // Step 10: Log final outcome.
            info!("Multi‑tier Vault infrastructure setup complete!");
            info!(
                "Root Vault ({}): Root Token: {}",
                root_addr, root_init.root_token
            );
            if !root_init.keys.is_empty() {
                info!("Unseal Keys: {:?}", root_init.keys);
            }
            info!("PKI Role: {}", root_role);
            info!(
                "Sub Vault ({}): Root Token: {}",
                sub_addr, sub_init.root_token
            );
            if let Some(recovery_keys) = &sub_init.recovery_keys {
                info!("Recovery Keys: {:?}", recovery_keys);
            }
            info!("Intermediate PKI Role: {}", int_role);

            // Optionally save credentials to file.
            if let Some(path) = output_file {
                let mut out = String::new();
                out.push_str("# Root Vault Credentials\n");
                out.push_str(&format!("Root Token: {}\n", root_init.root_token));
                if !root_init.keys.is_empty() {
                    out.push_str("Unseal Keys:\n");
                    for key in &root_init.keys {
                        out.push_str(&format!("{}\n", key));
                    }
                }
                out.push_str("\n# Sub Vault Credentials\n");
                out.push_str(&format!("Root Token: {}\n", sub_init.root_token));
                if let Some(recovery_keys) = &sub_init.recovery_keys {
                    out.push_str("Recovery Keys:\n");
                    for key in recovery_keys {
                        out.push_str(&format!("{}\n", key));
                    }
                }
                fs::write(&path, out)?;
                info!("Credentials saved to {}", path);
            }
        }
    }
    Ok(())
}
