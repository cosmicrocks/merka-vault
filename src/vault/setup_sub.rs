// src/vault/setup_sub.rs

use anyhow::{anyhow, Result};
use tracing::info;

use crate::vault::autounseal;
use crate::vault::common::{check_vault_status, wait_for_vault_availability};
use crate::vault::init::InitResult;
use crate::vault::pki;

/// Input config for "setup-sub" step
#[derive(Debug, Clone)]
pub struct SubSetupConfig {
    pub sub_addr: String,
    pub domain: String,
    pub ttl: String,

    // We need the root vault's address & token to sign the intermediate
    pub root_addr: String,
    pub root_token: String,
}

/// Output from "setup-sub"
#[derive(Debug, Clone)]
pub struct SubSetupResult {
    pub sub_init: InitResult,
    /// For demonstration, returning the roles or cert info
    pub pki_roles: (String, String),
}

/// Actually set up the sub vault with auto-unseal + PKI intermediate.
/// We expect the sub vault already has VAULT_TOKEN set to the unwrapped token from step 1.
pub async fn setup_sub_vault(config: SubSetupConfig) -> Result<SubSetupResult> {
    let SubSetupConfig {
        sub_addr,
        domain,
        ttl,
        root_addr,
        root_token,
    } = config;

    // 1) Ensure sub vault is up. In a real scenario you might wait for it:
    wait_for_vault_availability(&sub_addr, std::time::Duration::from_secs(30)).await?;
    // Check if sub vault is already initialized or not
    let status = check_vault_status(&sub_addr).await?;
    if status.initialized {
        // either error or skip
        return Err(anyhow!(
            "Sub vault is already initialized. If you're re-running, provide sub's root token."
        ));
    }

    // 2) Actually call "init_with_autounseal"
    info!("Initializing sub vault with auto-unseal at {}...", sub_addr);
    let sub_init = autounseal::init_with_autounseal(&sub_addr).await?;
    info!("Sub vault root token = {}", sub_init.root_token);

    // 3) Do the PKI intermediate setup
    // We sign the sub vault's intermediate CA using the root vault
    // The function `setup_pki_intermediate` returns (cert_chain, role_name)
    info!(
        "Setting up intermediate PKI on sub vault. Root vault at {}",
        root_addr
    );
    let (_int_cert, int_role) = pki::setup_pki_intermediate(
        &root_addr,
        &root_token,
        &sub_addr,
        &sub_init.root_token,
        &domain,
        &ttl,
    )
    .await?;
    info!("Intermediate PKI is set: role={} chain-len=?", int_role);

    // You could do more config or store into DB here

    Ok(SubSetupResult {
        sub_init,
        // If you wanted to also store root role name, you might do so. For example:
        pki_roles: ("root-role??".to_string(), int_role),
    })
}
