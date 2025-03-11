//! Command-line interface for Vault provisioning.
//!
//! This file defines the CLI and its commands for initializing Vault,
//! unsealing, PKI setup, and authentication configuration using Vault.

use anyhow::Result;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use merka_vault::actor::VaultActor;
use merka_vault::vault::{self, operations::VaultOperations};
use std::error::Error;
use std::fs;
use std::path::Path;

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
        vault::init::init_vault(
            &self.vault_addr,
            secret_shares,
            secret_threshold,
            None,
            None,
        )
        .await
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

    async fn issue_certificate(
        &self,
        token: &str,
        domain: &str,
        common_name: &str,
        ttl: &str,
    ) -> Result<String, vault::VaultError> {
        let (cert, _) = vault::pki::issue_certificateificate(
            &self.vault_addr,
            token,
            domain,
            common_name,
            Some(ttl),
        )
        .await?;
        Ok(cert)
    }

    async fn setup_transit_engine(&self, token: &str) -> Result<(), vault::VaultError> {
        vault::transit::setup_transit_engine(&self.vault_addr, token).await
    }

    async fn create_transit_key(
        &self,
        token: &str,
        key_name: &str,
    ) -> Result<(), vault::VaultError> {
        vault::transit::create_transit_key(&self.vault_addr, token, key_name).await
    }

    async fn create_transit_unseal_policy(
        &self,
        token: &str,
        policy_name: &str,
        key_name: &str,
    ) -> Result<(), vault::VaultError> {
        vault::transit::create_transit_unseal_policy(&self.vault_addr, token, policy_name, key_name)
            .await
    }

    async fn generate_transit_unseal_token(
        &self,
        token: &str,
        policy_name: &str,
    ) -> Result<String, vault::VaultError> {
        vault::transit::generate_transit_unseal_token(&self.vault_addr, token, policy_name).await
    }

    async fn generate_wrapped_transit_unseal_token(
        &self,
        token: &str,
        policy_name: &str,
        ttl: u32,
    ) -> Result<String, vault::VaultError> {
        vault::autounseal::generate_wrapped_transit_unseal_token(
            &self.vault_addr,
            token,
            policy_name,
            ttl,
        )
        .await
    }

    async fn unwrap_token(&self, wrapped_token: &str) -> Result<String, vault::VaultError> {
        vault::autounseal::unwrap_token(&self.vault_addr, wrapped_token).await
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

/// Builds the CLI application with all subcommands and arguments.
/// Uses the newer Command-based API for clap.
pub fn build_cli() -> clap::Command {
    clap::Command::new("merka-vault")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("HashiCorp Vault management tool")
        .subcommand_required(true)
        .arg(
            clap::Arg::new("vault-addr")
                .long("vault-addr")
                .value_name("URL")
                .help("Vault server address")
                .default_value("http://127.0.0.1:8200"),
        )
        .arg(
            clap::Arg::new("token")
                .long("token")
                .value_name("TOKEN")
                .help("Vault token")
                .env("VAULT_TOKEN"),
        )
        .subcommand(
            clap::Command::new("init")
                .about("Initialize Vault")
                .arg(
                    clap::Arg::new("secret-shares")
                        .long("secret-shares")
                        .value_name("NUM")
                        .help("Number of key shares to split the master key into")
                        .default_value("5"),
                )
                .arg(
                    clap::Arg::new("secret-threshold")
                        .long("secret-threshold")
                        .value_name("NUM")
                        .help("Number of key shares required to reconstruct the master key")
                        .default_value("3"),
                )
                .arg(
                    clap::Arg::new("output")
                        .long("output")
                        .value_name("FILE")
                        .help("Save init keys and tokens to specified file"),
                ),
        )
        .subcommand(
            clap::Command::new("unseal")
                .about("Unseal Vault")
                .arg(
                    clap::Arg::new("keys-file")
                        .long("keys-file")
                        .value_name("FILE")
                        .help("File containing unseal keys (one per line)"),
                )
                .arg(
                    clap::Arg::new("key")
                        .long("key")
                        .value_name("KEY")
                        .help("Unseal key (can be specified multiple times)")
                        .action(clap::ArgAction::Append),
                ),
        )
        .subcommand(
            clap::Command::new("pki")
                .about("PKI operations")
                .subcommand(
                    clap::Command::new("setup")
                        .about("Set up PKI secrets engine")
                        .arg(
                            clap::Arg::new("common-name")
                                .long("common-name")
                                .value_name("CN")
                                .help("Common name for root certificate")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("ttl")
                                .long("ttl")
                                .value_name("TTL")
                                .help("TTL for the root certificate")
                                .default_value("87600h"),
                        )
                        .arg(
                            clap::Arg::new("use-intermediate")
                                .long("use-intermediate")
                                .help("Setup intermediate CA"),
                        )
                        .arg(
                            clap::Arg::new("intermediate-addr")
                                .long("intermediate-addr")
                                .value_name("URL")
                                .help("Intermediate CA Vault address"),
                        )
                        .arg(
                            clap::Arg::new("intermediate-token")
                                .long("intermediate-token")
                                .value_name("TOKEN")
                                .help("Intermediate CA Vault token"),
                        ),
                )
                .subcommand(
                    clap::Command::new("issue")
                        .about("Issue certificate")
                        .arg(
                            clap::Arg::new("domain")
                                .long("domain")
                                .value_name("DOMAIN")
                                .help("Domain for the certificate")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("common-name")
                                .long("common-name")
                                .value_name("CN")
                                .help("Common name for certificate")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("ttl")
                                .long("ttl")
                                .value_name("TTL")
                                .help("TTL for the certificate")
                                .default_value("720h"),
                        )
                        .arg(
                            clap::Arg::new("output")
                                .long("output")
                                .value_name("FILE")
                                .help("Output file for the certificate"),
                        ),
                ),
        )
        .subcommand(
            clap::Command::new("auth")
                .about("Authentication method operations")
                .subcommand(
                    clap::Command::new("approle")
                        .about("Set up AppRole authentication")
                        .arg(
                            clap::Arg::new("role-name")
                                .long("role-name")
                                .value_name("NAME")
                                .help("AppRole role name")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("policy")
                                .long("policy")
                                .value_name("POLICY")
                                .help("Policy to attach to the role (can be specified multiple times)")
                                .action(clap::ArgAction::Append)
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("output")
                                .long("output")
                                .value_name("FILE")
                                .help("Output file for the credentials"),
                        ),
                )
                .subcommand(
                    clap::Command::new("kubernetes")
                        .about("Set up Kubernetes authentication")
                        .arg(
                            clap::Arg::new("role-name")
                                .long("role-name")
                                .value_name("NAME")
                                .help("Kubernetes role name")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("service-account")
                                .long("service-account")
                                .value_name("SA")
                                .help("Kubernetes service account name")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("namespace")
                                .long("namespace")
                                .value_name("NS")
                                .help("Kubernetes namespace")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("kubernetes-host")
                                .long("kubernetes-host")
                                .value_name("HOST")
                                .help("Kubernetes API server host")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("kubernetes-ca-cert")
                                .long("kubernetes-ca-cert")
                                .value_name("CERT")
                                .help("Kubernetes CA certificate file path")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            clap::Command::new("transit")
                .about("Transit encryption operations for auto-unseal")
                .subcommand(
                    clap::Command::new("setup")
                        .about("Set up Transit engine")
                )
                .subcommand(
                    clap::Command::new("create-key")
                        .about("Create a new transit key")
                        .arg(
                            clap::Arg::new("key-name")
                                .long("key-name")
                                .value_name("NAME")
                                .help("Name for the transit key")
                                .required(true),
                        )
                )
                .subcommand(
                    clap::Command::new("create-policy")
                        .about("Create a policy for transit auto-unseal")
                        .arg(
                            clap::Arg::new("policy-name")
                                .long("policy-name")
                                .value_name("NAME")
                                .help("Name for the policy")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("key-name")
                                .long("key-name")
                                .value_name("NAME")
                                .help("Transit key name to reference in the policy")
                                .required(true),
                        )
                )
                .subcommand(
                    clap::Command::new("generate-token")
                        .about("Generate a token for transit auto-unseal")
                        .arg(
                            clap::Arg::new("policy-name")
                                .long("policy-name")
                                .value_name("NAME")
                                .help("Policy to attach to the token")
                                .required(true),
                        )
                        .arg(
                            clap::Arg::new("output")
                                .long("output")
                                .value_name("FILE")
                                .help("Output file for the token"),
                        )
                )
        )
}

/// Runs the CLI application with the given arguments.
pub async fn run(matches: &clap::ArgMatches) -> Result<(), Box<dyn Error>> {
    let vault_addr = matches.get_one::<String>("vault-addr").unwrap();
    let token = matches.get_one::<String>("token").map(|s| s.as_str());

    let mut actor = VaultActor::new(vault_addr);
    if let Some(t) = token {
        actor.root_token = Some(t.to_string());
    }

    match matches.subcommand() {
        Some(("init", sub_m)) => {
            let secret_shares = sub_m
                .get_one::<String>("secret-shares")
                .unwrap()
                .parse::<u8>()?;
            let secret_threshold = sub_m
                .get_one::<String>("secret-threshold")
                .unwrap()
                .parse::<u8>()?;

            println!("Initializing Vault at: {}", vault_addr);
            let init_result = actor.init_vault(secret_shares, secret_threshold).await?;
            println!("Vault initialized successfully!");
            println!("Root Token: {}", init_result.root_token);
            println!("Unseal Keys:");
            for (i, key) in init_result.keys.iter().enumerate() {
                println!("  Key {}: {}", i + 1, key);
            }

            if let Some(output_file) = sub_m.get_one::<String>("output") {
                let path = Path::new(output_file);
                let mut output = String::new();
                output.push_str(&format!("Root Token: {}\n", init_result.root_token));
                output.push_str("Unseal Keys:\n");
                for key in &init_result.keys {
                    output.push_str(&format!("{}\n", key));
                }
                fs::write(path, output)?;
                println!("Credentials saved to: {}", output_file);
            }

            // Update actor with the root token
            actor.root_token = Some(init_result.root_token);
        }

        Some(("unseal", sub_m)) => {
            let mut unseal_keys = Vec::new();

            // Get keys from file if provided
            if let Some(keys_file) = sub_m.get_one::<String>("keys-file") {
                let contents = fs::read_to_string(keys_file)?;
                for line in contents.lines() {
                    if !line.starts_with("Root Token:") && !line.starts_with("Unseal Keys:") {
                        let key = line.trim();
                        if !key.is_empty() {
                            unseal_keys.push(key.to_string());
                        }
                    }
                }
            }

            // Add keys from command line
            if let Some(keys) = sub_m.get_many::<String>("key") {
                for key in keys {
                    unseal_keys.push(key.to_string());
                }
            }

            if unseal_keys.is_empty() {
                return Err("No unseal keys provided".into());
            }

            println!("Unsealing Vault with {} keys", unseal_keys.len());
            actor.unseal_vault(&unseal_keys).await?;
            println!("Vault unsealed successfully!");
        }

        Some(("pki", pki_matches)) => match pki_matches.subcommand() {
            Some(("setup", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for PKI setup")?;

                let common_name = sub_m.get_one::<String>("common-name").unwrap();
                let ttl = sub_m.get_one::<String>("ttl").unwrap();
                let use_intermediate = sub_m.contains_id("use-intermediate");
                let int_addr = sub_m
                    .get_one::<String>("intermediate-addr")
                    .map(|s| s.to_string());
                let int_token = sub_m
                    .get_one::<String>("intermediate-token")
                    .map(|s| s.to_string());

                println!("Setting up PKI secrets engine");
                let (cert, role_name) = actor
                    .setup_pki(
                        &token,
                        common_name,
                        ttl,
                        use_intermediate,
                        int_addr.as_deref(),
                        int_token.as_deref(),
                    )
                    .await?;

                println!("PKI setup complete!");
                println!("CA Certificate: \n{}", cert);
                println!("Role Name: {}", role_name);
            }
            Some(("issue", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for certificate issuance")?;

                let domain = sub_m.get_one::<String>("domain").unwrap();
                let common_name = sub_m.get_one::<String>("common-name").unwrap();
                let ttl = sub_m.get_one::<String>("ttl").unwrap();

                println!("Issuing certificate for: {}", common_name);
                let cert = actor
                    .issue_certificate(&token, domain, common_name, ttl)
                    .await?;
                println!("Certificate issued successfully!");

                if let Some(output_file) = sub_m.get_one::<String>("output") {
                    fs::write(output_file, &cert)?;
                    println!("Certificate saved to: {}", output_file);
                } else {
                    println!("Certificate: \n{}", cert);
                }
            }
            _ => {
                return Err("Unknown PKI subcommand".into());
            }
        },

        Some(("auth", auth_matches)) => match auth_matches.subcommand() {
            Some(("approle", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for AppRole setup")?;

                let role_name = sub_m.get_one::<String>("role-name").unwrap();
                let policies: Vec<String> = sub_m
                    .get_many::<String>("policy")
                    .unwrap()
                    .map(|s| s.to_string())
                    .collect();

                println!("Setting up AppRole authentication for role: {}", role_name);
                let creds = actor.setup_approle(&token, role_name, &policies).await?;
                println!("AppRole setup complete!");
                println!("Role ID: {}", creds.role_id);
                println!("Secret ID: {}", creds.secret_id);

                if let Some(output_file) = sub_m.get_one::<String>("output") {
                    let output = format!(
                        "Role ID: {}\nSecret ID: {}\n",
                        creds.role_id, creds.secret_id
                    );
                    fs::write(output_file, output)?;
                    println!("Credentials saved to: {}", output_file);
                }
            }
            Some(("kubernetes", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for Kubernetes auth setup")?;

                let role_name = sub_m.get_one::<String>("role-name").unwrap();
                let service_account = sub_m.get_one::<String>("service-account").unwrap();
                let namespace = sub_m.get_one::<String>("namespace").unwrap();
                let kubernetes_host = sub_m.get_one::<String>("kubernetes-host").unwrap();
                let kubernetes_ca_cert_path =
                    sub_m.get_one::<String>("kubernetes-ca-cert").unwrap();
                let kubernetes_ca_cert = fs::read_to_string(kubernetes_ca_cert_path)?;

                println!(
                    "Setting up Kubernetes authentication for role: {}",
                    role_name
                );
                actor
                    .setup_kubernetes_auth(
                        &token,
                        role_name,
                        service_account,
                        namespace,
                        kubernetes_host,
                        &kubernetes_ca_cert,
                    )
                    .await?;
                println!("Kubernetes authentication setup complete!");
            }
            _ => {
                return Err("Unknown auth subcommand".into());
            }
        },

        Some(("transit", transit_matches)) => match transit_matches.subcommand() {
            Some(("setup", _)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for Transit setup")?;

                println!("Setting up Transit secrets engine");
                actor.setup_transit_engine(&token).await?;
                println!("Transit secrets engine setup complete!");
            }
            Some(("create-key", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for creating Transit key")?;

                let key_name = sub_m.get_one::<String>("key-name").unwrap();

                println!("Creating Transit key: {}", key_name);
                actor.create_transit_key(&token, key_name).await?;
                println!("Transit key created successfully!");
            }
            Some(("create-policy", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for creating policy")?;

                let policy_name = sub_m.get_one::<String>("policy-name").unwrap();
                let key_name = sub_m.get_one::<String>("key-name").unwrap();

                println!("Creating policy for Transit auto-unseal: {}", policy_name);
                actor
                    .create_transit_unseal_policy(&token, policy_name, key_name)
                    .await?;
                println!("Transit auto-unseal policy created successfully!");
            }
            Some(("generate-token", sub_m)) => {
                let token = actor
                    .root_token
                    .clone()
                    .ok_or("Root token is required for generating token")?;

                let policy_name = sub_m.get_one::<String>("policy-name").unwrap();

                println!("Generating token with policy: {}", policy_name);
                let unseal_token = actor
                    .generate_transit_unseal_token(&token, policy_name)
                    .await?;
                println!("Token generated successfully!");
                println!("Unseal Token: {}", unseal_token);

                if let Some(output_file) = sub_m.get_one::<String>("output") {
                    fs::write(
                        output_file,
                        &format!("TRANSIT_UNSEAL_TOKEN={}\n", unseal_token),
                    )?;
                    println!("Token saved to: {}", output_file);
                }
            }
            _ => {
                return Err("Unknown transit subcommand".into());
            }
        },

        _ => {
            return Err("Unknown command".into());
        }
    }

    Ok(())
}
