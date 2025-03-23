use anyhow::{anyhow, Result};
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, warn};

use crate::vault::common::wait_for_vault_availability;
use crate::vault::setup_root::{setup_root_vault, RootSetupConfig, RootSetupResult};
use crate::vault::setup_sub::{setup_sub_vault, SubSetupConfig, SubSetupResult};

// Configuration for the setup wizard
pub struct WizardConfig {
    pub root_addr: String,
    pub sub_addr: String,
    pub domain: String,
    pub ttl: String,
    pub secret_shares: u8,
    pub secret_threshold: u8,
    pub key_name: String,
    pub mode: String,
    pub output_file: Option<String>,
}

impl Default for WizardConfig {
    fn default() -> Self {
        WizardConfig {
            root_addr: "http://127.0.0.1:8200".to_string(),
            sub_addr: "http://127.0.0.1:8202".to_string(),
            domain: "example.com".to_string(),
            ttl: "8760h".to_string(),
            secret_shares: 1,
            secret_threshold: 1,
            key_name: "autounseal-key".to_string(),
            mode: "local".to_string(),
            output_file: Some("vault-setup.txt".to_string()),
        }
    }
}

// Result of the setup wizard
pub struct WizardResult {
    pub root_result: Option<RootSetupResult>,
    pub sub_result: Option<SubSetupResult>,
}

// Check if Docker is running and has the vault containers
async fn check_docker_vaults() -> Result<bool> {
    let output = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()?;

    if !output.status.success() {
        warn!("Docker command failed, assuming Docker is not running");
        return Ok(false);
    }

    let output_str = String::from_utf8(output.stdout)?;
    let has_root = output_str.contains("merka-vault-root");
    let has_sub = output_str.contains("merka-vault-sub");

    Ok(has_root || has_sub)
}

// Check if a port is in use, suggesting a vault might be running there
async fn check_port_in_use(host: &str, port: u16) -> bool {
    let client = Client::new();
    let url = format!("{}:{}/v1/sys/health", host, port);

    match client
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(_response) => {
            // If we get any response (even an error), it suggests something is listening
            true
        }
        Err(_) => false,
    }
}

// Run the interactive setup wizard
pub async fn run_setup_wizard() -> Result<WizardResult> {
    println!("==== Merka Vault Setup Wizard ====");
    println!("This wizard will guide you through setting up root and sub vaults.");

    // Check if running in Docker environment
    let docker_running = check_docker_vaults().await?;
    if docker_running {
        println!("Detected Docker running with Vault containers!");
    } else {
        println!("No Docker Vault containers detected. We'll use standard addresses.");
    }

    // Start with default config
    let mut config = WizardConfig::default();

    // Allow user to choose setup mode
    let setup_options = vec![
        "Setup both Root and Sub vaults",
        "Setup Root vault only",
        "Setup Sub vault only",
    ];
    let setup_selection = Select::new()
        .with_prompt("What would you like to set up?")
        .items(&setup_options)
        .default(0)
        .interact()?;

    let setup_root = setup_selection == 0 || setup_selection == 1;
    let setup_sub = setup_selection == 0 || setup_selection == 2;

    // Configuration questions
    if setup_root {
        // Root vault address
        config.root_addr = Input::new()
            .with_prompt("Root vault address")
            .default(config.root_addr)
            .interact_text()?;

        // Check if vault is already running at this address
        let root_available = check_port_in_use("http://127.0.0.1", 8200).await;
        if root_available {
            println!("Detected a service running at the root vault address!");
        }

        // Shamir shares config
        config.secret_shares = Input::new()
            .with_prompt("Number of secret shares")
            .default(config.secret_shares)
            .interact_text()?;

        config.secret_threshold = Input::new()
            .with_prompt("Number of shares required to unseal")
            .default(config.secret_threshold)
            .interact_text()?;

        // Auto-unseal key name
        config.key_name = Input::new()
            .with_prompt("Transit auto-unseal key name")
            .default(config.key_name)
            .interact_text()?;

        // Output file for credentials
        let save_to_file = Confirm::new()
            .with_prompt("Save credentials to a file?")
            .default(true)
            .interact()?;

        if save_to_file {
            config.output_file = Some(
                Input::new()
                    .with_prompt("Output file path")
                    .default(
                        config
                            .output_file
                            .unwrap_or_else(|| "vault-setup.txt".to_string()),
                    )
                    .interact_text()?,
            );
        } else {
            config.output_file = None;
        }
    }

    if setup_sub {
        // Only ask for root address/token if we're not setting up root
        if !setup_root {
            config.root_addr = Input::new()
                .with_prompt("Root vault address")
                .default(config.root_addr)
                .interact_text()?;
        }

        // Sub vault address
        config.sub_addr = Input::new()
            .with_prompt("Sub vault address")
            .default(config.sub_addr)
            .interact_text()?;

        // Domain for PKI
        config.domain = Input::new()
            .with_prompt("Domain for PKI certificates")
            .default(config.domain)
            .interact_text()?;

        // TTL for certificates
        config.ttl = Input::new()
            .with_prompt("Certificate TTL (e.g. 8760h for 1 year)")
            .default(config.ttl)
            .interact_text()?;
    }

    // Summary and confirmation
    println!("\n==== Setup Summary ====");
    if setup_root {
        println!("Root Vault Address: {}", config.root_addr);
        println!("Secret Shares: {}", config.secret_shares);
        println!("Secret Threshold: {}", config.secret_threshold);
        println!("Auto-unseal Key: {}", config.key_name);
        if let Some(file) = &config.output_file {
            println!("Output File: {}", file);
        }
    }

    if setup_sub {
        println!("Sub Vault Address: {}", config.sub_addr);
        println!("Domain for PKI: {}", config.domain);
        println!("Certificate TTL: {}", config.ttl);
    }

    let confirmed = Confirm::new()
        .with_prompt("Continue with this configuration?")
        .default(true)
        .interact()?;

    if !confirmed {
        return Err(anyhow!("Setup cancelled by user"));
    }

    // Create result container
    let mut result = WizardResult {
        root_result: None,
        sub_result: None,
    };

    // Execute the setup process with progress indicators
    if setup_root {
        println!("\n==== Setting up Root Vault ====");
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.green} {msg}")?,
        );
        pb.set_message("Initializing root vault...");

        // Setup root vault
        let root_config = RootSetupConfig {
            root_addr: config.root_addr.clone(),
            secret_shares: config.secret_shares,
            secret_threshold: config.secret_threshold,
            key_name: config.key_name.clone(),
            mode: config.mode.clone(),
            output_file: config.output_file.clone(),
        };

        match setup_root_vault(root_config).await {
            Ok(root_result) => {
                pb.finish_with_message("Root vault setup complete!");
                println!("Root token: {}", root_result.root_init.root_token);
                println!(
                    "Unwrapped token for sub vault: {}",
                    root_result.unwrapped_token
                );

                // Save result for return
                result.root_result = Some(root_result.clone());

                // If we're also setting up sub vault, wait a moment for the user to read
                if setup_sub {
                    println!("\nPreparing for sub vault setup...");
                    sleep(Duration::from_secs(2)).await;
                }
            }
            Err(e) => {
                pb.finish_with_message(format!("Root vault setup failed: {}", e));
                error!("Root vault setup error: {}", e);

                // If root setup fails and we need it for sub setup, abort
                if setup_sub {
                    return Err(anyhow!("Cannot continue with sub vault setup: {}", e));
                }
            }
        }
    }

    // Setup sub vault if requested
    if setup_sub {
        // If we don't have a root result (from earlier in this process), we need a root token
        let root_token = if let Some(root_result) = &result.root_result {
            root_result.root_init.root_token.clone()
        } else {
            println!("\n==== Root Token Required ====");
            Input::<String>::new()
                .with_prompt("Enter root vault token")
                .interact_text()?
        };

        let _unwrapped_token = if let Some(root_result) = &result.root_result {
            println!("\n==== Sub Vault Preparation ====");
            println!("You need to restart the sub vault with the unwrapped token:");
            println!(
                "VAULT_TOKEN={} docker-compose up -d sub-vault",
                root_result.unwrapped_token
            );

            let run_command = Confirm::new()
                .with_prompt("Would you like me to run this command for you?")
                .default(true)
                .interact()?;

            if run_command {
                println!("Attempting to restart the sub vault with the unwrapped token...");
                let docker_cmd = format!(
                    "VAULT_TOKEN={} docker-compose up -d sub-vault",
                    root_result.unwrapped_token
                );
                let status = Command::new("sh").arg("-c").arg(&docker_cmd).status()?;

                if status.success() {
                    println!("Sub vault container started successfully!");

                    // Wait a few seconds for the container to initialize
                    println!("Waiting for the sub vault to initialize...");
                    sleep(Duration::from_secs(5)).await;
                } else {
                    println!("Failed to start sub vault container. You may need to run the command manually:");
                    println!(
                        "VAULT_TOKEN={} docker-compose up -d sub-vault",
                        root_result.unwrapped_token
                    );

                    let ready_to_continue = Confirm::new()
                        .with_prompt("Have you manually restarted the sub vault with the token?")
                        .default(false)
                        .interact()?;

                    if !ready_to_continue {
                        return Err(anyhow!("Setup cancelled - please restart the sub vault with the token and run setup again"));
                    }
                }
            } else {
                let ready_to_continue = Confirm::new()
                    .with_prompt("Have you restarted the sub vault with the token?")
                    .default(false)
                    .interact()?;

                if !ready_to_continue {
                    return Err(anyhow!("Setup cancelled - please restart the sub vault with the token and run setup again"));
                }
            }

            root_result.unwrapped_token.clone()
        } else {
            println!("Starting sub vault with auto-unseal token...");

            if docker_running {
                println!("Detected Docker environment. To start the sub vault, run:");
                println!("VAULT_TOKEN=<your_unwrapped_token> docker-compose up -d sub-vault");

                let use_docker = Confirm::new()
                    .with_prompt("Would you like me to attempt starting the sub vault via Docker?")
                    .default(true)
                    .interact()?;

                if use_docker {
                    // Get the unwrapped token from user
                    let token = Input::<String>::new()
                        .with_prompt("Enter the unwrapped token for auto-unseal")
                        .interact_text()?;

                    // Try to start the sub vault container
                    let docker_cmd =
                        format!("VAULT_TOKEN={} docker-compose up -d sub-vault", token);
                    let status = Command::new("sh").arg("-c").arg(&docker_cmd).status()?;

                    if status.success() {
                        println!("Sub vault container started successfully!");
                    } else {
                        return Err(anyhow!("Failed to start sub vault container"));
                    }

                    // Wait for sub vault to be available
                    println!("Waiting for sub vault to become available...");
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(
                        ProgressStyle::default_spinner()
                            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                            .template("{spinner:.green} {msg}")?,
                    );

                    let max_retries = 30;
                    let mut retry_count = 0;

                    while retry_count < max_retries {
                        pb.set_message(format!(
                            "Checking sub vault availability (attempt {}/{})",
                            retry_count + 1,
                            max_retries
                        ));

                        match wait_for_vault_availability(&config.sub_addr, Duration::from_secs(1))
                            .await
                        {
                            Ok(_) => {
                                pb.finish_with_message("Sub vault is now available!");
                                break;
                            }
                            Err(_) => {
                                retry_count += 1;
                                sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }

                    if retry_count == max_retries {
                        return Err(anyhow!(
                            "Sub vault did not become available within the timeout period"
                        ));
                    }

                    token
                } else {
                    // If not using Docker automation, ensure user has started the vault
                    let token = Input::<String>::new()
                        .with_prompt("Enter the unwrapped token for auto-unseal")
                        .interact_text()?;

                    println!("To start the sub vault with this token, run:");
                    println!("VAULT_TOKEN={} docker-compose up -d sub-vault", token);

                    let run_command = Confirm::new()
                        .with_prompt("Would you like me to run this command for you?")
                        .default(true)
                        .interact()?;

                    if run_command {
                        println!("Attempting to restart the sub vault with the token...");
                        let docker_cmd =
                            format!("VAULT_TOKEN={} docker-compose up -d sub-vault", token);
                        let status = Command::new("sh").arg("-c").arg(&docker_cmd).status()?;

                        if status.success() {
                            println!("Sub vault container started successfully!");

                            // Wait a few seconds for the container to initialize
                            println!("Waiting for the sub vault to initialize...");
                            sleep(Duration::from_secs(5)).await;
                        } else {
                            println!("Failed to start sub vault container. You may need to run the command manually.");

                            let ready_to_continue = Confirm::new()
                                .with_prompt(
                                    "Have you manually started the sub vault with the token?",
                                )
                                .default(false)
                                .interact()?;

                            if !ready_to_continue {
                                return Err(anyhow!("Setup cancelled - please start the sub vault with the token and run setup again"));
                            }
                        }
                    } else {
                        let ready_to_continue = Confirm::new()
                            .with_prompt("Have you started the sub vault with this token?")
                            .default(false)
                            .interact()?;

                        if !ready_to_continue {
                            return Err(anyhow!("Setup cancelled - please start the sub vault with the token and run setup again"));
                        }
                    }

                    token
                }
            } else {
                let token = Input::<String>::new()
                    .with_prompt("Enter the unwrapped token for auto-unseal")
                    .interact_text()?;

                println!("Please start the sub vault with this token.");
                println!("Example command (if using standard setup):");
                println!(
                    "VAULT_TOKEN={} vault server -config=/path/to/sub-vault.hcl",
                    token
                );

                let ready_to_continue = Confirm::new()
                    .with_prompt("Have you started the sub vault with this token?")
                    .default(false)
                    .interact()?;

                if !ready_to_continue {
                    return Err(anyhow!("Setup cancelled - please start the sub vault with the token and run setup again"));
                }

                token
            }
        };

        println!("\n==== Setting up Sub Vault ====");
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.green} {msg}")?,
        );
        pb.set_message("Initializing sub vault with auto-unseal and PKI...");

        // Setup sub vault
        let sub_config = SubSetupConfig {
            sub_addr: config.sub_addr.clone(),
            domain: config.domain.clone(),
            ttl: config.ttl.clone(),
            root_addr: config.root_addr.clone(),
            root_token,
        };

        match setup_sub_vault(sub_config).await {
            Ok(sub_result) => {
                pb.finish_with_message("Sub vault setup complete!");
                println!("Sub vault root token: {}", sub_result.sub_init.root_token);
                println!("PKI role established: {}", sub_result.pki_roles.1);

                // Save result for return
                result.sub_result = Some(sub_result);
            }
            Err(e) => {
                pb.finish_with_message(format!("Sub vault setup failed: {}", e));
                error!("Sub vault setup error: {}", e);
            }
        }
    }

    println!("\n==== Setup Complete ====");
    println!("Thank you for using the Merka Vault setup wizard!");

    Ok(result)
}
