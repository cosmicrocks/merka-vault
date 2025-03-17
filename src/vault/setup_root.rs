// src/vault/setup_root.rs

use anyhow::{anyhow, Result};
use tracing::{info, warn};

use crate::vault::autounseal;
use crate::vault::common::{check_vault_status, wait_for_vault_unseal};
use crate::vault::init::{init_vault, unseal_root_vault, InitResult};
use crate::vault::transit;

/// Input config for the "setup-root" step.
#[derive(Debug, Clone)]
pub struct RootSetupConfig {
    pub root_addr: String,
    pub secret_shares: u8,
    pub secret_threshold: u8,
    pub key_name: String,
    pub mode: String,
    pub output_file: Option<String>,
}

/// Output of the "setup-root" step:
/// - `root_init`: the complete initialization result including root token and keys
/// - `unwrapped_token`: the final unwrapped token for sub Vault auto-unseal
#[derive(Debug, Clone)]
pub struct RootSetupResult {
    pub root_init: InitResult,
    pub unwrapped_token: String,
}

/// Sets up the **root** Vault for auto‐unseal:
///  1. Initialize/unseal root Vault (if needed)
///  2. Enable transit engine + create key
///  3. Generate a wrapped token, unwrap it locally
///  4. Return the unwrapped token so user can inject it into sub Vault
pub async fn setup_root_vault(config: RootSetupConfig) -> Result<RootSetupResult> {
    let RootSetupConfig {
        root_addr,
        secret_shares,
        secret_threshold,
        key_name,
        mode,
        output_file,
    } = config;

    info!(
        "Checking if root vault at {} is already initialized...",
        root_addr
    );

    // 1) check if already init
    let status = check_vault_status(&root_addr).await?;
    let root_init = if !status.initialized {
        info!("Root vault not initialized; proceeding with init...");
        let init_result = init_vault(
            &root_addr,
            secret_shares,
            secret_threshold,
            None, // recovery_shares (unused if you're using shamir)
            None, // recovery_threshold
        )
        .await?;
        info!(
            "Root vault init done. Root token = {}",
            init_result.root_token
        );

        // unseal
        let unseal_res = unseal_root_vault(&root_addr, init_result.keys.clone()).await?;
        if unseal_res.sealed {
            warn!(
                "Vault still sealed after unseal attempts; progress={}",
                unseal_res.progress
            );
        }
        init_result
    } else {
        info!("Root vault is already initialized. Provide the root token or retrieve it from DB.");
        // If you're storing tokens in DB, you can load them. For example:
        // If you do not have the user-supplied token, we can error:
        return Err(anyhow!("Root vault is already initialized; please provide root token or use DB to retrieve it."));
    };

    // ensure it's unsealed
    wait_for_vault_unseal(&root_addr, std::time::Duration::from_secs(60)).await?;
    info!("Root vault is unsealed and ready.");

    // 2) enable transit + create key + create policy
    info!("Setting up transit auto-unseal on root vault...");
    autounseal::setup_transit_autounseal(&root_addr, &root_init.root_token, &key_name).await?;
    info!("Transit engine + unseal policy set up successfully.");

    // 3) generate a short-lived, wrapped token and unwrap it
    let wrap_ttl = "300s";
    let wrapped_token = transit::generate_wrapped_transit_token(
        &root_addr,
        &root_init.root_token,
        "autounseal", // policy name used in setup_transit_autounseal
        wrap_ttl,
    )
    .await?;
    let unwrapped_token = autounseal::unwrap_token(&root_addr, &wrapped_token).await?;
    info!(
        "Successfully unwrapped the transit token for sub vault = {}",
        unwrapped_token
    );

    // 4) maybe write the root & unwrapped tokens to a file
    if let Some(path) = output_file {
        use std::fs;
        let mut out = String::new();
        out.push_str("# Root Vault Setup:\n");
        out.push_str(&format!("Root token: {}\n", root_init.root_token));
        if !root_init.keys.is_empty() {
            out.push_str("Unseal keys:\n");
            for k in &root_init.keys {
                out.push_str(&format!("  {}\n", k));
            }
        }
        out.push_str("\n# Sub Vault unwrapped token:\n");
        out.push_str(&format!("  {}\n", unwrapped_token));
        fs::write(&path, out)?;
        info!("Wrote root credentials + unwrapped sub token to {}", path);
    }

    // Print instructions if local mode, etc.
    if mode == "local" {
        info!("Local mode: You must now update your sub-vault container env with the unwrapped token.");
        info!(
            "Example: export VAULT_TOKEN={} && docker-compose up -d sub-vault",
            unwrapped_token
        );
    } else {
        info!("Remote mode: copy/paste the token into your helm chart or environment for the sub vault");
    }

    Ok(RootSetupResult {
        root_init,
        unwrapped_token,
    })
}
