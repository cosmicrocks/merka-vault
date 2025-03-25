//! CLI module for the Merka Vault library
//!
//! This module implements the command-line interface for the Merka Vault library.
//! It can use both the actor-based API (preferred) and the direct vault API.
//!
//! Architectural constraints:
//! - The CLI module may use both the actor and vault modules
//! - The CLI module should prefer using the actor for stateful operations

use anyhow::Result;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use std::fs;
use tracing::info;

use crate::interface::VaultInterface;
use crate::vault::common::VaultStatus;
use crate::vault::{UnsealResult, VaultError};

// --- Import the new two-step setup logic ---
use crate::vault::setup_root::{setup_root_vault, RootSetupConfig, RootSetupResult};
use crate::vault::setup_sub::{setup_sub_vault, SubSetupConfig, SubSetupResult};
use crate::vault::wizard::run_setup_wizard;

#[derive(Parser)]
#[command(
    name = "merka-vault",
    about = "Vault provisioning CLI (supports unseal, status, and multi-step setup)",
    version = "0.2.0"
)]
pub struct Cli {
    /// Default root Vault server address (used if subcommands don't override).
    #[arg(long, default_value = "http://127.0.0.1:8200", env = "ROOT_VAULT_ADDR")]
    pub vault_addr: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all known vaults and their status
    List,

    /// Unseal Vault.
    Unseal {
        /// Provide one or more unseal keys
        #[arg(long, value_name = "UNSEAL_KEY")]
        keys: Vec<String>,

        /// Optionally read keys from a file
        #[arg(long)]
        keys_file: Option<String>,
    },

    /// Check Vault status.
    Status {
        /// Optionally override which Vault address to check
        #[arg(long)]
        vault_addr: Option<String>,
    },

    /// Interactive setup wizard for vault provisioning
    Setup,

    /// (Step 1) Set up the root Vault for auto‐unseal, generating an unwrapped token
    SetupRoot {
        /// The root Vault's address (override the CLI default)
        #[arg(long, default_value = "http://127.0.0.1:8200")]
        root_addr: String,

        /// Shamir shares & threshold
        #[arg(long, default_value_t = 1)]
        secret_shares: u8,

        #[arg(long, default_value_t = 1)]
        secret_threshold: u8,

        /// Transit key name
        #[arg(long, default_value = "autounseal-key")]
        key_name: String,

        /// Local or remote mode
        #[arg(long, default_value = "local")]
        mode: String,

        /// Optional output file
        #[arg(long)]
        output_file: Option<String>,
    },

    /// (Step 2) Set up the sub Vault for auto‐unseal + intermediate PKI
    SetupSub {
        /// Sub Vault address
        #[arg(long, default_value = "http://127.0.0.1:8202")]
        sub_addr: String,

        /// Domain name for PKI
        #[arg(long, default_value = "example.com")]
        domain: String,

        /// TTL for PKI certs
        #[arg(long, default_value = "8760h")]
        ttl: String,

        /// Root Vault address (if needed to sign the intermediate)
        #[arg(long)]
        root_addr: Option<String>,

        /// Root Vault token
        #[arg(long)]
        root_token: String,
    },

    /// Get an unwrapped transit token for auto-unseal from a root vault
    GetTransitToken {
        /// The root Vault's address
        #[arg(long, default_value = "http://127.0.0.1:8200")]
        root_addr: String,

        /// Root Vault token
        #[arg(long)]
        root_token: String,

        /// Transit key name
        #[arg(long, default_value = "autounseal-key")]
        key_name: String,
    },

    /// Start the web server with API endpoints for vault management
    Server {
        /// The address to listen on
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen_addr: String,

        /// The default vault address
        #[arg(long, default_value = "http://127.0.0.1:8200")]
        vault_addr: String,

        /// Path to the SQLite database
        #[arg(long, default_value = "merka_vault.db")]
        db_path: String,
    },
}

// -------------------------------------------------------------------
// Optionally, your existing VaultCli that implements VaultInterface
// -------------------------------------------------------------------
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

    async fn setup_root(
        &self,
        addr: &str,
        secret_shares: u8,
        secret_threshold: u8,
        key_name: &str,
    ) -> Result<String, VaultError> {
        let config = RootSetupConfig {
            root_addr: addr.to_string(),
            secret_shares,
            secret_threshold,
            key_name: key_name.to_string(),
            mode: "local".to_string(),
            output_file: None,
        };

        match setup_root_vault(config).await {
            Ok(RootSetupResult {
                root_init,
                unwrapped_token,
            }) => {
                info!(
                    "Root Vault setup is complete. Root token = {}",
                    root_init.root_token
                );
                Ok(unwrapped_token)
            }
            Err(e) => Err(VaultError::Api(format!("Root setup error: {}", e))),
        }
    }

    async fn setup_sub(
        &self,
        root_addr: &str,
        root_token: &str,
        sub_addr: &str,
        domain: &str,
        ttl: &str,
    ) -> Result<String, VaultError> {
        let config = SubSetupConfig {
            sub_addr: sub_addr.to_string(),
            domain: domain.to_string(),
            ttl: ttl.to_string(),
            root_addr: root_addr.to_string(),
            root_token: root_token.to_string(),
        };

        match setup_sub_vault(config).await {
            Ok(SubSetupResult {
                sub_init,
                pki_roles,
            }) => {
                info!(
                    "Sub Vault is auto-unsealed: root token = {}",
                    sub_init.root_token
                );
                Ok(pki_roles.1)
            }
            Err(e) => Err(VaultError::Api(format!("Sub setup error: {}", e))),
        }
    }

    async fn get_unwrapped_transit_token(
        &self,
        root_addr: &str,
        root_token: &str,
        key_name: &str,
    ) -> Result<String, VaultError> {
        // First, ensure transit auto-unseal is set up
        if let Err(e) =
            crate::vault::autounseal::setup_transit_autounseal(root_addr, root_token, key_name)
                .await
        {
            return Err(VaultError::Api(format!(
                "Failed to setup transit auto-unseal: {}",
                e
            )));
        }

        // Generate a wrapped transit token
        let wrap_ttl = "300s";
        let wrapped_token = match crate::vault::transit::generate_wrapped_transit_token(
            root_addr,
            root_token,
            "autounseal", // policy name used in setup_transit_autounseal
            wrap_ttl,
        )
        .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(VaultError::Api(format!(
                    "Failed to generate wrapped token: {}",
                    e
                )))
            }
        };

        // Unwrap the token
        let unwrapped_token =
            match crate::vault::autounseal::unwrap_token(root_addr, &wrapped_token).await {
                Ok(token) => token,
                Err(e) => return Err(VaultError::Api(format!("Failed to unwrap token: {}", e))),
            };

        info!("Got unwrapped token for auto-unseal: {}", unwrapped_token);

        Ok(unwrapped_token)
    }
}

// -------------------------------------------------------------------
// The main CLI runner that processes commands
// -------------------------------------------------------------------
/// Run the CLI application
///
/// This function implements the CLI logic, using either the actor-based API
/// or the direct vault API depending on the operation being performed.
pub async fn run_cli() -> Result<()> {
    // Parse CLI args
    let cli = Cli::parse();
    let vault_cli = VaultCli;

    match cli.command {
        Commands::Status { vault_addr } => {
            // Use the vault_addr override if supplied, otherwise use the global cli.vault_addr.
            let addr = vault_addr.as_deref().unwrap_or(&cli.vault_addr);

            info!("Checking Vault status at {}", addr);
            let status = vault_cli.check_status(addr).await?;

            println!("Vault Status for {}:", addr);
            println!("  Initialized: {}", status.initialized);
            println!("  Sealed: {}", status.sealed);
            if status.sealed {
                println!("  Seal Progress: {}/{}", status.progress, status.t);
            }
            println!("  Version: {}", status.version);
        }

        Commands::Unseal { keys, keys_file } => {
            // Process keys from command line args and/or file
            let mut all_keys = keys;
            if let Some(file) = keys_file {
                let file_content = fs::read_to_string(file)?;
                let file_keys: Vec<String> = file_content
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.trim().to_string())
                    .collect();
                all_keys.extend(file_keys);
            }

            info!("Unsealing Vault with {} keys", all_keys.len());
            let unseal_result = vault_cli.unseal(&cli.vault_addr, all_keys).await?;

            println!("Unseal operation result:");
            println!("  Sealed: {}", unseal_result.sealed);
            println!(
                "  Progress: {}/{}",
                unseal_result.progress, unseal_result.threshold
            );
            if !unseal_result.sealed {
                println!("  Success: Vault is now unsealed!");
            } else {
                println!(
                    "  Additional keys needed: {} more",
                    unseal_result.threshold - unseal_result.progress
                );
            }
        }

        Commands::SetupRoot {
            root_addr,
            secret_shares,
            secret_threshold,
            key_name,
            mode,
            output_file,
        } => {
            let config = RootSetupConfig {
                root_addr,
                secret_shares,
                secret_threshold,
                key_name,
                mode,
                output_file,
            };

            let result = setup_root_vault(config).await?;
            println!(
                "Root setup complete! Root token: {}",
                result.root_init.root_token
            );
            println!("Unwrapped token for sub-vault: {}", result.unwrapped_token);
        }

        Commands::SetupSub {
            root_addr,
            root_token,
            sub_addr,
            domain,
            ttl,
        } => {
            let root_addr = root_addr.unwrap_or_else(|| cli.vault_addr.clone());
            let config = SubSetupConfig {
                sub_addr,
                domain,
                ttl,
                root_addr,
                root_token,
            };

            let result = setup_sub_vault(config).await?;
            println!(
                "Sub vault setup complete! Root token: {}",
                result.sub_init.root_token
            );
            println!("PKI role: {}", result.pki_roles.1);
        }

        Commands::Setup => {
            println!("Starting the interactive setup wizard...");
            match run_setup_wizard().await {
                Ok(result) => {
                    println!("Setup wizard completed successfully!");
                    if let Some(root_result) = result.root_result {
                        println!("Root Vault setup: SUCCESS");
                        println!("Root token: {}", root_result.root_init.root_token);
                    }
                    if let Some(sub_result) = result.sub_result {
                        println!("Sub Vault setup: SUCCESS");
                        println!("Sub token: {}", sub_result.sub_init.root_token);
                    }
                }
                Err(e) => {
                    println!("Setup wizard encountered an error: {}", e);
                    return Err(e);
                }
            }
        }

        Commands::GetTransitToken {
            root_addr,
            root_token,
            key_name,
        } => {
            let token = vault_cli
                .get_unwrapped_transit_token(&root_addr, &root_token, &key_name)
                .await?;
            println!("Unwrapped transit token: {}", token);
        }

        Commands::List => {
            // The list command could check for vaults in known locations or
            // vaults configured in a config file.
            println!("Known vaults:");
            println!("  Root vault: {}", cli.vault_addr);
            match vault_cli.check_status(&cli.vault_addr).await {
                Ok(status) => {
                    println!("    Initialized: {}", status.initialized);
                    println!("    Sealed: {}", status.sealed);
                }
                Err(e) => {
                    println!("    Status: Error - {}", e);
                }
            }

            // Try the sub vault at standard port
            let sub_addr = cli.vault_addr.replace(":8200", ":8202");
            match vault_cli.check_status(&sub_addr).await {
                Ok(status) => {
                    println!("  Sub vault: {}", sub_addr);
                    println!("    Initialized: {}", status.initialized);
                    println!("    Sealed: {}", status.sealed);
                }
                Err(_) => {
                    println!("  Sub vault: Not detected at {}", sub_addr);
                }
            }
        }

        Commands::Server {
            listen_addr,
            vault_addr,
            db_path,
        } => {
            println!("Starting the web server on {}...", listen_addr);
            println!("Using vault at: {}", vault_addr);
            println!("Database path: {}", db_path);

            // Run the server (this is a blocking call)
            crate::server::start_server(&listen_addr, &vault_addr, &db_path).await?;
        }
    }

    Ok(())
}
