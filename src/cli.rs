use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::fs;

// Replace api imports with vault module imports
use crate::vault::{
    autounseal,
    common::check_vault_status,
    init::{initialize_vault_infrastructure, unseal_root_vault, InitOptions},
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
    /// Unseal Vault (calls /v1/sys/unseal)
    Unseal {
        /// Provide one or more unseal keys.
        #[arg(long, value_name = "UNSEAL_KEY")]
        keys: Vec<String>,
        /// Optionally read keys from a file.
        #[arg(long)]
        keys_file: Option<String>,
    },
    /// Check Vault status (sealed/unsealed, initialized)
    Status {
        /// Specify the Vault address to check (defaults to root vault)
        #[arg(long)]
        vault_addr: Option<String>,
    },
    /// Set up a complete multi-tier infrastructure with auto-unseal and PKI
    Setup {
        /// Root Vault address
        #[arg(long, default_value = "http://127.0.0.1:8200", env = "ROOT_VAULT_ADDR")]
        root_addr: String,
        /// Sub-vault address that will be auto-unsealed
        #[arg(long, default_value = "http://127.0.0.1:8202", env = "SUB_VAULT_ADDR")]
        sub_addr: String,
        /// Secret shares for initialization
        #[arg(long, default_value_t = 1)]
        secret_shares: u8,
        /// Secret threshold for initialization
        #[arg(long, default_value_t = 1)]
        secret_threshold: u8,
        /// Domain name for PKI setup
        #[arg(long, default_value = "example.com")]
        domain: String,
        /// TTL for certificates
        #[arg(long, default_value = "8760h")]
        ttl: String,
        /// Name for auto-unseal key
        #[arg(long, default_value = "autounseal-key")]
        key_name: String,
        /// Optional output file to save credentials
        #[arg(long)]
        output_file: Option<String>,
    },
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
            println!("Unseal result: sealed = {}", result.sealed);
            println!("Progress: {}/{}", result.progress, result.threshold);
        }
        Commands::Status { vault_addr } => {
            let addr = vault_addr.unwrap_or_else(|| cli.vault_addr.clone());
            info!("Checking status of Vault at {}", addr);
            match check_vault_status(&addr).await {
                Ok(status) => {
                    println!("Vault Status:");
                    println!("  Initialized: {}", status.initialized);
                    println!("  Sealed: {}", status.sealed);
                    println!("  Standby: {}", status.standby);
                    if !status.sealed && status.initialized {
                        println!("  Active Node: Yes");
                    }

                    if !status.initialized {
                        println!("\nVault is not initialized. Run the setup command to initialize and configure the vault.");
                    } else if status.sealed {
                        println!("\nVault is sealed. Run the unseal command to unseal.");
                    }
                }
                Err(e) => {
                    println!("Error checking Vault status: {}", e);

                    // Check if the error might be due to connection issues
                    if e.to_string().contains("connect") || e.to_string().contains("connection") {
                        println!("\nConnection error: Ensure Vault is running at {}", addr);
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
        } => {
            info!("Setting up multi-tier Vault infrastructure:");
            info!("  Root Vault: {}", root_addr);
            info!("  Sub Vault: {}", sub_addr);

            // Step 1: Initialize and unseal the root Vault
            info!("Initializing root Vault...");
            let root_init_options = InitOptions {
                secret_shares,
                secret_threshold,
            };
            let root_init = initialize_vault_infrastructure(&root_addr, root_init_options).await?;
            info!(
                "Root Vault initialized with token: {}",
                root_init.root_token
            );

            // Step 2: Set up transit engine on root vault for auto-unseal
            info!("Setting up transit auto-unseal on root Vault...");
            autounseal::setup_transit_autounseal(&root_addr, &root_init.root_token, &key_name)
                .await?;

            // Step 3: Configure sub vault for auto-unseal using root vault
            info!("Configuring sub Vault for auto-unseal...");
            autounseal::configure_vault_for_autounseal(
                &sub_addr,
                &root_addr,
                &root_init.root_token,
                &key_name,
            )
            .await?;

            // Step 4: Initialize sub vault with auto-unseal
            info!("Initializing sub Vault with auto-unseal...");
            let sub_init = autounseal::init_with_autounseal(&sub_addr).await?;
            info!("Sub Vault initialized with token: {}", sub_init.root_token);

            // Step 5: Set up PKI on root vault
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

            // Step 6: Set up intermediate PKI on sub vault
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

            // Output the results
            println!("Multi-tier Vault infrastructure setup complete!");
            println!("\nRoot Vault ({}):", root_addr);
            println!("  Root Token: {}", root_init.root_token);
            println!("  Unseal Keys:");
            for (i, key) in root_init.keys.iter().enumerate() {
                println!("    Key {}: {}", i + 1, key);
            }
            println!("  PKI Role: {}", root_role);

            println!("\nSub Vault ({}):", sub_addr);
            println!("  Root Token: {}", sub_init.root_token);
            println!("  Auto-unsealed using transit engine from root Vault");
            if let Some(recovery_keys) = &sub_init.recovery_keys {
                println!("  Recovery Keys:");
                for (i, key) in recovery_keys.iter().enumerate() {
                    println!("    Key {}: {}", i + 1, key);
                }
            }
            println!("  Intermediate PKI Role: {}", int_role);

            // Save credentials to file if requested
            if let Some(path) = output_file {
                let mut out = String::new();
                out.push_str("# Root Vault Credentials\n");
                out.push_str(&format!("Root Token: {}\n", root_init.root_token));
                out.push_str("Unseal Keys:\n");
                for key in &root_init.keys {
                    out.push_str(&format!("{}\n", key));
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
                println!("\nCredentials saved to {}", path);
            }
        }
    }
    Ok(())
}
