//! Command-line interface for Vault provisioning.
//!
//! This file defines the CLI and its commands for initializing Vault,
//! unsealing, PKI setup, and authentication configuration using Vault.

use anyhow::Result;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use merka_vault::vault::{self, operations::VaultOperations};

pub struct VaultCli {
    pub vault_addr: String,
}

#[async_trait]
impl VaultOperations for VaultCli {
    async fn init_vault(
        &self,
        secret_shares: u8,
        secret_threshold: u8,
    ) -> Result<vault::InitResult, vault::VaultError> {
        vault::init::init_vault(&self.vault_addr, secret_shares, secret_threshold).await
    }

    async fn unseal_vault(&self, keys: &[String]) -> Result<(), vault::VaultError> {
        vault::init::unseal_vault(&self.vault_addr, keys).await
    }

    async fn setup_pki(
        &self,
        token: &str,
        domain: &str,
        ttl: &str,
        use_intermediate: bool,
        int_addr: Option<&str>,
        int_token: Option<&str>,
    ) -> Result<(String, String), vault::VaultError> {
        vault::pki::setup_pki(
            &self.vault_addr,
            token,
            domain,
            ttl,
            use_intermediate,
            int_addr,
            int_token,
        )
        .await
    }

    async fn setup_approle(
        &self,
        token: &str,
        role_name: &str,
        policies: &[String],
    ) -> Result<merka_vault::vault::AppRoleCredentials, vault::VaultError> {
        vault::auth::setup_approle(&self.vault_addr, token, role_name, policies).await
    }

    async fn setup_kubernetes_auth(
        &self,
        token: &str,
        role_name: &str,
        service_account: &str,
        namespace: &str,
        kubernetes_host: &str,
        kubernetes_ca_cert: &str,
    ) -> Result<(), vault::VaultError> {
        vault::auth::setup_kubernetes_auth(
            &self.vault_addr,
            token,
            role_name,
            service_account,
            namespace,
            kubernetes_host,
            kubernetes_ca_cert,
        )
        .await
    }

    async fn issue_cert(
        &self,
        token: &str,
        domain: &str,
        common_name: &str,
        ttl: &str,
    ) -> Result<String, vault::VaultError> {
        let (cert, _) =
            vault::pki::issue_certificate(&self.vault_addr, token, domain, common_name, Some(ttl))
                .await?;
        Ok(cert)
    }
}

#[derive(Parser)]
#[command(
    name = "merka-vault",
    about = "Vault provisioning CLI",
    version = "0.1.0"
)]
pub struct Cli {
    /// Vault server address
    #[arg(
        long,
        default_value = "http://127.0.0.1:8200",
        global = true,
        env = "VAULT_ADDR"
    )]
    pub vault_addr: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new Vault and generate unseal keys
    Init {
        #[arg(long, default_value_t = 1)]
        secret_shares: u8,
        #[arg(long, default_value_t = 1)]
        secret_threshold: u8,
    },
    /// Unseal the Vault with provided key shares
    Unseal {
        #[arg(long = "key", value_name = "UNSEAL_KEY", required = true)]
        keys: Vec<String>,
    },
    /// Set up the PKI secrets engine (root and/or intermediate)
    SetupPki {
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        #[arg(long)]
        domain: String,
        #[arg(long, default_value = "8760h")]
        ttl: String,
        #[arg(long)]
        intermediate: bool,
        #[arg(long, requires = "int_token")]
        int_vault_addr: Option<String>,
        #[arg(long, requires = "int_vault_addr")]
        int_token: Option<String>,
    },
    /// Set up authentication backends (AppRole, Kubernetes)
    Auth {
        #[command(subcommand)]
        method: AuthMethod,
    },
}

#[derive(Subcommand)]
pub enum AuthMethod {
    AppRole {
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        #[arg(long)]
        role_name: String,
        #[arg(
            long,
            value_delimiter = ',',
            use_value_delimiter = true,
            default_value = "default"
        )]
        policies: Vec<String>,
    },
    Kubernetes {
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        #[arg(long)]
        role_name: String,
        #[arg(long)]
        service_account: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        kubernetes_host: String,
        #[arg(long)]
        kubernetes_ca_cert: String,
    },
}

/// Runs the CLI command dispatcher.
pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let addr = cli.vault_addr;
    let vault_cli = VaultCli {
        vault_addr: addr.clone(),
    };

    match cli.command {
        Commands::Init {
            secret_shares,
            secret_threshold,
        } => {
            let init_result = vault_cli.init_vault(secret_shares, secret_threshold).await;
            match init_result {
                Ok(res) => {
                    println!("Vault initialized successfully!");
                    println!("Root Token: {}", res.root_token);
                    println!(
                        "Unseal Keys ({}/{} needed):",
                        res.keys.len(),
                        secret_threshold
                    );
                    for key in res.keys {
                        println!(" - {}", key);
                    }
                }
                Err(err) => {
                    eprintln!("Error initializing Vault: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Commands::Unseal { keys } => match vault_cli.unseal_vault(&keys).await {
            Ok(_) => println!("Vault unsealed successfully!"),
            Err(err) => {
                eprintln!("Error unsealing Vault: {}", err);
                std::process::exit(1);
            }
        },
        Commands::SetupPki {
            token,
            domain,
            ttl,
            intermediate,
            int_vault_addr,
            int_token,
        } => {
            let use_int = intermediate || int_vault_addr.is_some();
            let result = vault_cli
                .setup_pki(
                    &token,
                    &domain,
                    &ttl,
                    use_int,
                    int_vault_addr.as_deref(),
                    int_token.as_deref(),
                )
                .await;
            match result {
                Ok((cert, role_name)) => {
                    if use_int {
                        println!(
                            "Root and intermediate PKI configured. CA certificate chain:\n{}",
                            cert
                        );
                    } else {
                        println!("PKI engine configured. CA Certificate:\n{}", cert);
                    }
                    println!("PKI role '{}' created for domain '{}'.", role_name, domain);
                }
                Err(err) => {
                    eprintln!("Error setting up PKI: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Commands::Auth { method } => match method {
            AuthMethod::AppRole {
                token,
                role_name,
                policies,
            } => {
                let result = vault_cli.setup_approle(&token, &role_name, &policies).await;
                match result {
                    Ok(creds) => {
                        println!("AppRole '{}' created.", role_name);
                        println!("Role ID: {}", creds.role_id);
                        println!("Secret ID: {}", creds.secret_id);
                    }
                    Err(err) => {
                        eprintln!("Error setting up AppRole: {}", err);
                        std::process::exit(1);
                    }
                }
            }
            AuthMethod::Kubernetes {
                token,
                role_name,
                service_account,
                namespace,
                kubernetes_host,
                kubernetes_ca_cert,
            } => {
                let result = vault_cli
                    .setup_kubernetes_auth(
                        &token,
                        &role_name,
                        &service_account,
                        &namespace,
                        &kubernetes_host,
                        &kubernetes_ca_cert,
                    )
                    .await;
                match result {
                    Ok(_) => {
                        println!(
                            "Kubernetes auth configured. Role '{}' mapped to service account '{}:{}'.",
                            role_name, namespace, service_account
                        );
                    }
                    Err(err) => {
                        eprintln!("Error setting up Kubernetes auth: {}", err);
                        std::process::exit(1);
                    }
                }
            }
        },
    }
    Ok(())
}
