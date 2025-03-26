use actix::{Actor, Addr};
use anyhow::{Context, Result};
use log::info;
use merka_vault::actor::{
    AddUnsealerRelationship, AutoUnseal, CheckStatus, GetUnwrappedTransitToken, InitVault,
    SetRootToken, SetupPki, SetupRoot, SetupSub, SetupTransit, StatusInfo, UnsealVault, VaultActor,
    VaultEvent,
};
use merka_vault::database::DatabaseManager;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;

/// Creates a VaultActor with an event channel and optional database
#[allow(dead_code)]
pub fn create_actor(
    vault_addr: &str,
    db_path: Option<&str>,
) -> (Addr<VaultActor>, broadcast::Receiver<VaultEvent>) {
    let (tx, rx) = broadcast::channel(100);

    let actor = if let Some(path) = db_path {
        info!("Creating VaultActor with database at {}", path);
        match DatabaseManager::new(path) {
            Ok(db) => VaultActor::new(vault_addr, Some(tx.clone())).with_database(db),
            Err(e) => {
                info!(
                    "Failed to create database: {}, using actor without database",
                    e
                );
                VaultActor::new(vault_addr, Some(tx.clone()))
            }
        }
    } else {
        info!("Creating VaultActor without database");
        VaultActor::new(vault_addr, Some(tx.clone()))
    };

    (actor.start(), rx)
}

/// Initialize a vault with the actor
#[allow(dead_code)]
pub async fn initialize_vault(
    actor: &Addr<VaultActor>,
    secret_shares: u8,
    secret_threshold: u8,
) -> Result<(String, Vec<String>)> {
    info!(
        "Initializing vault with {} shares, threshold {}",
        secret_shares, secret_threshold
    );

    let message_result = actor
        .send(InitVault {
            secret_shares,
            secret_threshold,
        })
        .await
        .context("Failed to send InitVault message to actor")?;

    let init_result = message_result.context("Actor failed to process InitVault message")?;

    info!("Vault initialized successfully");
    Ok((init_result.root_token, init_result.keys))
}

/// Unseal a vault with the actor
#[allow(dead_code)]
pub async fn unseal_vault(actor: &Addr<VaultActor>, keys: Vec<String>) -> Result<bool> {
    info!("Unsealing vault with {} keys", keys.len());

    // First unseal the vault
    let message_result = actor
        .send(UnsealVault { keys })
        .await
        .context("Failed to send UnsealVault message to actor")?;

    let unseal_result = message_result.context("Actor failed to process UnsealVault message")?;

    info!("Unseal result: sealed={}", unseal_result.sealed);

    // Then check status to confirm
    let status = check_status(actor).await?;

    info!(
        "Vault status after unseal: initialized={}, sealed={}",
        status.initialized, status.sealed
    );

    Ok(!status.sealed)
}

/// Set up a root vault with the actor
#[allow(dead_code)]
pub async fn setup_root_vault(
    actor: &Addr<VaultActor>,
    addr: &str,
    secret_shares: u8,
    secret_threshold: u8,
    key_name: &str,
) -> Result<String> {
    info!("Setting up root vault at {}", addr);

    let message_result = actor
        .send(SetupRoot {
            addr: addr.to_string(),
            secret_shares,
            secret_threshold,
            key_name: key_name.to_string(),
        })
        .await
        .context("Failed to send SetupRoot message to actor")?;

    let unwrapped_token = message_result.context("Actor failed to process SetupRoot message")?;

    info!("Root vault setup complete, received unwrapped token");
    Ok(unwrapped_token)
}

/// Set up a sub vault with the actor
#[allow(dead_code)]
pub async fn setup_sub_vault(
    actor: &Addr<VaultActor>,
    root_addr: &str,
    root_token: &str,
    sub_addr: &str,
    domain: &str,
    ttl: &str,
) -> Result<String> {
    info!(
        "Setting up sub vault at {} with root at {}",
        sub_addr, root_addr
    );

    let message_result = actor
        .send(SetupSub {
            root_addr: root_addr.to_string(),
            root_token: root_token.to_string(),
            sub_addr: sub_addr.to_string(),
            domain: domain.to_string(),
            ttl: ttl.to_string(),
        })
        .await
        .context("Failed to send SetupSub message to actor")?;

    let int_role = message_result.context("Actor failed to process SetupSub message")?;

    info!(
        "Sub vault setup complete, received intermediate role name: {}",
        int_role
    );
    Ok(int_role)
}

/// Set up transit auto-unseal
#[allow(dead_code)]
pub async fn setup_transit(
    actor: &Addr<VaultActor>,
    token: &str,
    key_name: &str,
) -> Result<String> {
    info!("Setting up transit auto-unseal with key {}", key_name);

    let message_result = actor
        .send(SetupTransit {
            token: token.to_string(),
            key_name: key_name.to_string(),
        })
        .await
        .context("Failed to send SetupTransit message to actor")?;

    let key_name = message_result.context("Actor failed to process SetupTransit message")?;

    info!("Transit setup complete, key name: {}", key_name);
    Ok(key_name)
}

/// Get unwrapped transit token for auto-unseal
#[allow(dead_code)]
pub async fn get_unwrapped_transit_token(
    actor: &Addr<VaultActor>,
    root_addr: &str,
    root_token: &str,
    key_name: &str,
) -> Result<String> {
    info!("Getting unwrapped transit token from {}", root_addr);

    let message_result = actor
        .send(GetUnwrappedTransitToken {
            root_addr: root_addr.to_string(),
            root_token: root_token.to_string(),
            key_name: key_name.to_string(),
        })
        .await
        .context("Failed to send GetUnwrappedTransitToken message to actor")?;

    let unwrapped_token =
        message_result.context("Actor failed to process GetUnwrappedTransitToken message")?;

    info!("Received unwrapped transit token");
    Ok(unwrapped_token)
}

/// Initialize a vault with auto-unseal
#[allow(dead_code)]
pub async fn auto_unseal_vault(actor: &Addr<VaultActor>) -> Result<(String, Option<Vec<String>>)> {
    info!("Initializing vault with auto-unseal");

    let message_result = actor
        .send(AutoUnseal)
        .await
        .context("Failed to send AutoUnseal message to actor")?;

    let result = message_result.context("Actor failed to process AutoUnseal message")?;

    info!("Auto-unsealed vault with token: {}", result.root_token);
    Ok((result.root_token, result.recovery_keys))
}

/// Register an auto-unseal relationship between vaults
#[allow(dead_code)]
pub async fn register_unsealer_relationship(
    actor: &Addr<VaultActor>,
    sub_addr: &str,
    root_addr: &str,
) -> Result<()> {
    info!(
        "Registering unsealer relationship: {} -> {}",
        sub_addr, root_addr
    );

    let message_result = actor
        .send(AddUnsealerRelationship {
            sub_addr: sub_addr.to_string(),
            root_addr: root_addr.to_string(),
        })
        .await
        .context("Failed to send AddUnsealerRelationship message to actor")?;

    message_result.context("Actor failed to process AddUnsealerRelationship message")?;

    info!("Registered unsealer relationship between sub vault and root vault");
    Ok(())
}

/// Set the root token for an actor
#[allow(dead_code)]
pub async fn set_root_token(actor: &Addr<VaultActor>, token: &str) -> Result<()> {
    info!("Setting root token for actor");

    let message_result = actor
        .send(SetRootToken(token.to_string()))
        .await
        .context("Failed to send SetRootToken message to actor")?;

    message_result.context("Actor failed to process SetRootToken message")?;

    info!("Set root token for actor");
    Ok(())
}

/// Wait for a specific event with a timeout
#[allow(dead_code)]
pub async fn wait_for_event<T, F>(
    rx: &mut broadcast::Receiver<VaultEvent>,
    predicate: F,
    timeout_seconds: u64,
) -> Result<T>
where
    F: Fn(&VaultEvent) -> Option<T>,
{
    info!(
        "Waiting for event with timeout of {} seconds",
        timeout_seconds
    );
    let timeout_dur = Duration::from_secs(timeout_seconds);

    match timeout(timeout_dur, async {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Some(result) = predicate(&event) {
                        return Ok(result);
                    }
                    info!("Received event: {:?}", event);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Error receiving event: {}", e));
                }
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(e) => Err(anyhow::anyhow!("Timeout waiting for event: {}", e)),
    }
}

/// Setup PKI in a vault with the actor
#[allow(dead_code)]
pub async fn setup_pki(actor: &Addr<VaultActor>, role_name: &str) -> Result<(String, String)> {
    info!("Setting up PKI with role {}", role_name);

    let message_result = actor
        .send(SetupPki {
            role_name: role_name.to_string(),
        })
        .await
        .context("Failed to send SetupPki message to actor")?;

    let result = message_result.context("Actor failed to process SetupPki message")?;

    info!("PKI setup completed, role: {}", result.role_name);
    Ok((result.role_name, result.cert_chain))
}

/// Check vault status
#[allow(dead_code)]
pub async fn check_status(actor: &Addr<VaultActor>) -> Result<StatusInfo> {
    info!("Checking vault status");

    let message_result = actor
        .send(CheckStatus)
        .await
        .context("Failed to send CheckStatus message to actor")?;

    let status_info = message_result.context("Actor failed to process CheckStatus message")?;

    info!(
        "Vault status: initialized={}, sealed={}, standby={}",
        status_info.initialized, status_info.sealed, status_info.standby
    );

    Ok(status_info)
}
