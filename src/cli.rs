use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::fs;

use crate::actor;
use crate::api;
use crate::server;
use crate::vault::{autounseal, pki};

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
    /// Initialize Vault (calls /v1/sys/init)
    Init {
        #[arg(long, default_value_t = 1)]
        secret_shares: u8,
        #[arg(long, default_value_t = 1)]
        secret_threshold: u8,
        /// Optional output file to save credentials.
        #[arg(long)]
        output_file: Option<String>,
    },
    /// Unseal Vault (calls /v1/sys/unseal)
    Unseal {
        /// Provide one or more unseal keys.
        #[arg(long, value_name = "UNSEAL_KEY")]
        keys: Vec<String>,
        /// Optionally read keys from a file.
        #[arg(long)]
        keys_file: Option<String>,
    },
    /// Setup the PKI engine (root or intermediate).
    Pki {
        /// Domain name for the CA (e.g. "example.com").
        #[arg(long, default_value = "example.com")]
        domain: String,
        /// TTL for the certificate (e.g. "8760h").
        #[arg(long, default_value = "8760h")]
        ttl: String,
        /// Whether to use an intermediate CA (true/false).
        #[arg(long, default_value = "false")]
        intermediate: bool,
        /// Optional intermediate Vault address (if using a separate vault).
        #[arg(long)]
        intermediate_addr: Option<String>,
        /// Optional intermediate token (if using a separate vault).
        #[arg(long)]
        int_token: Option<String>,
    },
    /// Setup auto-unseal using the transit engine.
    Autounseal {
        /// Unsealer Vault address (which performs auto-unseal).
        #[arg(long, default_value = "http://127.0.0.1:8200", env = "UNSEALER_ADDR")]
        unsealer_addr: String,
        /// Target Vault address that should auto-unseal.
        #[arg(long, default_value = "http://127.0.0.1:8202", env = "TARGET_ADDR")]
        target_addr: String,
        /// Token to use (in dev mode, "root").
        #[arg(long, default_value = "root")]
        token: String,
        /// Key name for auto-unseal operations.
        #[arg(long, default_value = "autounseal-key")]
        key_name: String,
    },
    /// Run the API server (runs the actor alongside the HTTP server).
    ApiServer {
        /// Listen address for the API server.
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen_addr: String,
    },
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init {
            secret_shares,
            secret_threshold,
            output_file,
        } => {
            info!("Initializing Vault at {}", cli.vault_addr);
            let init_options = api::InitOptions {
                secret_shares,
                secret_threshold,
            };
            let result =
                api::initialize_vault_infrastructure(&cli.vault_addr, "", init_options).await?;
            println!("Vault initialized successfully!");
            println!("Root Token: {}", result.root_token);
            println!("Unseal Keys:");
            for (i, key) in result.keys.iter().enumerate() {
                println!("  Key {}: {}", i + 1, key);
            }
            if let Some(path) = output_file {
                let mut out = String::new();
                out.push_str(&format!("Root Token: {}\n", result.root_token));
                out.push_str("Unseal Keys:\n");
                for key in &result.keys {
                    out.push_str(&format!("{}\n", key));
                }
                fs::write(&path, out)?;
                println!("Credentials saved to {}", path);
            }
        }
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
            let result = api::unseal_root_vault(&cli.vault_addr, unseal_keys).await?;
            println!("Unseal result: sealed = {}", result.sealed);
            println!("Progress: {}/{}", result.progress, result.threshold);
        }
        Commands::Pki {
            domain,
            ttl,
            intermediate,
            intermediate_addr,
            int_token,
        } => {
            // Assume the Vault is already initialized and unsealed; use "root" token for simplicity.
            let token = "root";
            let (cert_chain, role_name) = pki::setup_pki(
                &cli.vault_addr,
                token,
                &domain,
                &ttl,
                intermediate,
                intermediate_addr.as_deref(),
                int_token.as_deref(),
            )
            .await?;
            println!("PKI setup complete!");
            println!("Certificate Chain:\n{}", cert_chain);
            println!("PKI Role Name: {}", role_name);
        }
        Commands::Autounseal {
            unsealer_addr,
            target_addr,
            token,
            key_name,
        } => {
            info!("Setting up auto-unseal:");
            info!("  Unsealer Vault: {}", unsealer_addr);
            info!("  Target Vault: {}", target_addr);
            autounseal::setup_transit_autounseal(&unsealer_addr, &token, &key_name).await?;
            autounseal::configure_vault_for_autounseal(
                &target_addr,
                &unsealer_addr,
                &token,
                &key_name,
            )
            .await?;
            let init_result = autounseal::init_with_autounseal(&target_addr).await?;
            println!("Auto-unseal initiated!");
            println!("Target Vault Root Token: {}", init_result.root_token);
            if let Some(recovery_keys) = init_result.recovery_keys {
                println!("Recovery Keys:");
                for key in recovery_keys {
                    println!("{}", key);
                }
            }
        }
        Commands::ApiServer { listen_addr } => {
            println!("Starting API server on {}", listen_addr);
            // Start the Vault actor with a channel.
            let (actor_addr, mut event_rx) = actor::start_vault_actor_with_channel(&cli.vault_addr);
            // Spawn a background task to forward events (e.g., to socket.io).
            actix_rt::spawn(async move {
                while let Ok(event) = event_rx.recv().await {
                    info!("VaultActor Event: {:?}", event);
                    // Here, push the event to connected socket.io clients.
                }
            });
            // Run the API server.
            server::run_api_server_async(&cli.vault_addr, "", &listen_addr).await?;
        }
    }
    Ok(())
}
