// src/main.rs
use clap::{Parser, Subcommand};
use merka_vault::vault;

#[derive(Parser)]
#[command(
    name = "merka-vault",
    about = "Vault provisioning CLI",
    version = "0.1.0"
)]
struct Cli {
    /// Vault server address
    #[arg(
        long,
        default_value = "http://127.0.0.1:8200",
        global = true,
        env = "VAULT_ADDR"
    )]
    vault_addr: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Vault and generate unseal keys
    Init {
        /// Number of key shares to split the master key into
        #[arg(long, default_value_t = 1)]
        secret_shares: u8,
        /// Number of key shares required to unseal
        #[arg(long, default_value_t = 1)]
        secret_threshold: u8,
    },
    /// Unseal the Vault with provided key shares
    Unseal {
        /// Unseal keys (provide all keys required by the threshold)
        #[arg(long = "key", value_name = "UNSEAL_KEY", required = true)]
        keys: Vec<String>,
    },
    /// Set up the PKI secrets engine (generate a root CA and default role)
    SetupPki {
        /// Vault root token for authentication (from init)
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        /// Common Name for the root certificate (e.g., domain name)
        #[arg(long)]
        domain: String,
        /// TTL for certificates (e.g., "8760h" for one year)
        #[arg(long, default_value = "8760h")]
        ttl: String,
    },
    /// Set up authentication backends (AppRole, Kubernetes)
    Auth {
        #[command(subcommand)]
        method: AuthMethod,
    },
}

#[derive(Subcommand)]
enum AuthMethod {
    /// Configure AppRole auth method and create a new AppRole
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
    /// Configure Kubernetes auth method and bind a Service Account
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let addr = cli.vault_addr;

    match cli.command {
        Commands::Init {
            secret_shares,
            secret_threshold,
        } => {
            // Initialize Vault
            let init_result = vault::init_vault(&addr, secret_shares, secret_threshold).await;
            match init_result {
                Ok(res) => {
                    println!("Vault initialized successfully!");
                    println!("Root Token: {}", res.root_token);
                    // For security, consider not printing unseal keys in real use, but here we show them:
                    println!(
                        "Unseal Keys ({}/{} needed):",
                        res.keys.len(),
                        secret_threshold
                    );
                    for key in &res.keys {
                        println!(" - {}", key);
                    }
                }
                Err(err) => {
                    eprintln!("Error initializing Vault: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Commands::Unseal { keys } => {
            let result = vault::unseal_vault(&addr, &keys).await;
            match result {
                Ok(_) => {
                    println!("Vault unsealed successfully!");
                }
                Err(err) => {
                    eprintln!("Error unsealing Vault: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Commands::SetupPki { token, domain, ttl } => {
            let result = vault::setup_pki(&addr, &token, &domain, &ttl).await;
            match result {
                Ok((cert, role_name)) => {
                    println!("PKI engine configured. CA Certificate:\n{}", cert);
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
                let result = vault::setup_approle(&addr, &token, &role_name, &policies).await;
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
                let result = vault::setup_kubernetes_auth(
                    &addr,
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
                        println!("Kubernetes auth configured. Role '{}' mapped to service account '{}:{}'.",
                                     role_name, namespace, service_account);
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
