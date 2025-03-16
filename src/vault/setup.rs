use anyhow::Result;
use std::fs;
use std::process::Command;
use std::time::Duration;
use tracing::info;

use crate::vault::{
    autounseal,
    common::{check_vault_status, wait_for_vault_availability, wait_for_vault_unseal},
    init::{
        init_vault, initialize_vault_infrastructure, unseal_root_vault, InitOptions, InitResult,
    },
    pki, transit,
};

#[derive(Debug, Clone)]
pub struct VaultSetupConfig {
    pub root_addr: String,
    pub sub_addr: String,
    pub secret_shares: u8,
    pub secret_threshold: u8,
    pub domain: String,
    pub ttl: String,
    pub key_name: String,
    pub output_file: Option<String>,
    pub root_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SetupResult {
    pub root_init: crate::vault::InitResult,
    pub root_role: String,
    pub sub_init: crate::vault::AutoUnsealResult,
    pub int_role: String,
}

pub struct VaultSetupResult {
    pub root_init: InitResult,
    pub sub_init: InitResult,
    pub root_role: String,
    pub int_role: String,
    pub root_cert: String,
    pub int_cert: String,
}

/// Fully automate multi‑tier Vault setup with auto‑unseal and PKI.
/// This function performs these steps:
/// 1. Initializes (if needed) and unseals the root Vault.
/// 2. Sets up the transit engine on the root Vault.
/// 3. Generates a wrapped token, unwraps it, and restarts the sub‑Vault container with the token injected.
/// 4. Waits for the sub‑Vault to unseal.
/// 5. Proceeds with PKI setup on both Vaults.
pub async fn setup_multi_tier_vault(config: VaultSetupConfig) -> Result<VaultSetupResult> {
    info!("Starting multi‑tier Vault infrastructure setup:");
    info!("  Root Vault: {}", config.root_addr);
    info!("  Sub Vault: {}", config.sub_addr);

    // Step 1: Initialize (if needed) and unseal the root Vault.
    let root_status = check_vault_status(&config.root_addr).await?;
    let root_init: InitResult;
    if (!root_status.initialized) {
        info!("Root Vault is not initialized.");
        let init_opts = InitOptions {
            secret_shares: config.secret_shares,
            secret_threshold: config.secret_threshold,
        };
        if (root_status.type_field == "shamir") {
            info!("Vault seal type is 'shamir'. Using secret_shares/secret_threshold.");
            root_init = initialize_vault_infrastructure(&config.root_addr, init_opts).await?;
        } else {
            info!(
                "Vault seal type is '{}'. Using recovery parameters.",
                root_status.type_field
            );
            root_init = init_vault(
                &config.root_addr,
                config.secret_shares,
                config.secret_threshold,
                Some(config.secret_shares),
                Some(config.secret_threshold),
            )
            .await?;
        }
        info!(
            "Root Vault initialized with token: {}",
            root_init.root_token
        );
        info!("Unsealing root Vault...");
        let unseal_result = unseal_root_vault(&config.root_addr, root_init.keys.clone()).await?;
        info!(
            "Root Vault unsealed: sealed = {}, progress = {}/{}",
            unseal_result.sealed, unseal_result.progress, unseal_result.threshold
        );
    } else {
        info!("Root Vault is already initialized.");
        if let Some(rt) = config.root_token {
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
                config.root_addr
            ));
        }
    }

    // Step 2: Wait for the root Vault to be unsealed.
    info!("Waiting for root Vault to be unsealed...");
    wait_for_vault_unseal(&config.root_addr, Duration::from_secs(60)).await?;

    // Step 3: Configure Transit engine on the root Vault.
    info!("Setting up transit auto‑unseal on root Vault...");
    autounseal::setup_transit_autounseal(
        &config.root_addr,
        &root_init.root_token,
        &config.key_name,
    )
    .await?;
    info!("Transit auto‑unseal setup completed on root Vault.");

    // Step 4: Generate a wrapped token and unwrap it.
    info!("Generating wrapped transit token...");
    let wrap_ttl = "300s";
    let wrapped_token = transit::generate_wrapped_transit_token(
        &config.root_addr,
        &root_init.root_token,
        "autounseal",
        wrap_ttl,
    )
    .await?;
    info!("Wrapped token obtained.");
    let unwrapped_token = autounseal::unwrap_token(&config.root_addr, &wrapped_token).await?;
    info!("Unwrapped token obtained.");

    // Step 5: Restart the sub Vault container with the new VAULT_TOKEN.
    info!("Restarting sub Vault container with updated VAULT_TOKEN...");
    let output = Command::new("docker-compose")
        .env("VAULT_TOKEN", unwrapped_token.clone())
        .args(&["up", "-d", "--force-recreate", "sub-vault"])
        .output()?;
    if (!output.status.success()) {
        info!(
            "Failed to restart sub‑vault container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        info!("Sub‑vault container restarted successfully.");
    }

    // Wait for the sub-vault to be available before initialization
    info!("Waiting for sub-vault to become available...");
    wait_for_vault_availability(&config.sub_addr, Duration::from_secs(30)).await?;

    // Step 6: Initialize the sub Vault with auto‑unseal.
    info!("Initializing sub Vault with auto‑unseal...");
    let sub_init = autounseal::init_with_autounseal(&config.sub_addr).await?;
    info!(
        "Sub Vault auto‑initialized with token: {}",
        sub_init.root_token
    );

    // Step 7: Wait for the sub Vault to be unsealed.
    info!("Waiting for sub Vault to be unsealed...");
    wait_for_vault_unseal(&config.sub_addr, Duration::from_secs(60)).await?;

    // Step 8: Set up PKI on the root Vault.
    info!("Setting up root PKI on root Vault...");
    let (root_cert, root_role) = pki::setup_pki(
        &config.root_addr,
        &root_init.root_token,
        &config.domain,
        &config.ttl,
        false,
        None,
        None,
    )
    .await?;
    info!("Root PKI setup complete. PKI Role: {}", root_role);

    // Step 9: Set up intermediate PKI on the sub Vault.
    info!("Setting up intermediate PKI on sub Vault...");
    let (int_cert, int_role) = pki::setup_pki_intermediate(
        &config.root_addr,
        &root_init.root_token,
        &config.sub_addr,
        &sub_init.root_token,
        &config.domain,
        &config.ttl,
    )
    .await?;
    info!(
        "Intermediate PKI setup complete. Intermediate PKI Role: {}",
        int_role
    );

    // Step 10: Log final outcome.
    info!("Multi‑tier Vault infrastructure setup complete!");

    // Optionally save credentials to file.
    if let Some(path) = config.output_file {
        let mut out = String::new();
        out.push_str("# Root Vault Credentials\n");
        out.push_str(&format!("Root Token: {}\n", root_init.root_token));
        if (!root_init.keys.is_empty()) {
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

    Ok(VaultSetupResult {
        root_init,
        sub_init,
        root_role,
        int_role,
        root_cert,
        int_cert,
    })
}
