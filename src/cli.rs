use anyhow::Result;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use std::fs;
use tracing::{error, info};

use crate::interface::VaultInterface;
use crate::vault::common::VaultStatus;
use crate::vault::setup::{SetupResult, VaultSetupConfig};
use crate::vault::{UnsealResult, VaultError};

#[derive(Parser)]
#[command(
    name = "merka-vault",
    about = "Vault provisioning CLI (supports unseal, status, and setup)",
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

// Implement the VaultInterface trait for handling CLI operations
pub struct VaultCli;

#[async_trait]
impl VaultInterface for VaultCli {
    async fn check_status(&self, addr: &str) -> Result<VaultStatus, VaultError> {
        match crate::vault::common::check_vault_status(addr).await {
            Ok(status) => Ok(status),
            Err(err) => Err(VaultError::Api(format!("Status check error: {}", err))),
        }
    }

    async fn unseal(&self, addr: &str, keys: Vec<String>) -> Result<UnsealResult, VaultError> {
        match crate::vault::init::unseal_root_vault(addr, keys).await {
            Ok(unseal_resp) => Ok(unseal_resp),
            Err(err) => Err(VaultError::Api(format!("Unseal error: {}", err))),
        }
    }

    async fn setup(&self, config: VaultSetupConfig) -> Result<SetupResult, VaultError> {
        match crate::vault::setup::setup_multi_tier_vault(config).await {
            Ok(result) => {
                let setup_result = SetupResult {
                    root_init: result.root_init,
                    root_role: result.root_role,
                    sub_init: crate::vault::AutoUnsealResult {
                        root_token: result.sub_init.root_token,
                        recovery_keys: result.sub_init.recovery_keys,
                        success: true,
                    },
                    int_role: result.int_role,
                };
                Ok(setup_result)
            }
            Err(err) => Err(VaultError::Api(format!("Setup error: {}", err))),
        }
    }
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let vault_cli = VaultCli {};

    match cli.command {
        Commands::Unseal { keys, keys_file } => {
            info!("Unsealing Vault at {}", cli.vault_addr);
            let mut unseal_keys = Vec::new();

            // Handle keys from file if provided
            if let Some(file) = keys_file {
                let contents = fs::read_to_string(file)?;
                for line in contents.lines() {
                    let line = line.trim();
                    if !line.is_empty() {
                        unseal_keys.push(line.to_string());
                    }
                }
            }

            // Add keys from command line
            unseal_keys.extend(keys);

            if unseal_keys.is_empty() {
                return Err(anyhow::anyhow!("No unseal keys provided"));
            }

            match vault_cli.unseal(&cli.vault_addr, unseal_keys).await {
                Ok(result) => {
                    info!("Unseal result: sealed = {}", result.sealed);
                    info!("Progress: {}/{}", result.progress, result.threshold);
                }
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to unseal vault: {}", err));
                }
            }
        }

        Commands::Status { vault_addr } => {
            let addr = vault_addr.unwrap_or_else(|| cli.vault_addr.clone());
            info!("Checking status of Vault at {}", addr);

            match vault_cli.check_status(&addr).await {
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
            root_token,
        } => {
            let config = VaultSetupConfig {
                root_addr,
                sub_addr,
                secret_shares,
                secret_threshold,
                domain,
                ttl,
                key_name,
                output_file,
                root_token,
            };

            match vault_cli.setup(config).await {
                Ok(result) => {
                    // Log the results
                    info!("Root Vault: Root Token: {}", result.root_init.root_token);
                    if !result.root_init.keys.is_empty() {
                        info!("Unseal Keys: {:?}", result.root_init.keys);
                    }
                    info!("PKI Role: {}", result.root_role);
                    info!("Sub Vault: Root Token: {}", result.sub_init.root_token);
                    if let Some(recovery_keys) = &result.sub_init.recovery_keys {
                        info!("Recovery Keys: {:?}", recovery_keys);
                    }
                    info!("Intermediate PKI Role: {}", result.int_role);
                }
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to setup vault: {}", err));
                }
            }
        }
    }
    Ok(())
}
