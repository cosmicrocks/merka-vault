//! tests/actor_integration.rs

mod common;
use actix_rt::time::{sleep, timeout};
use common::{init_logging, setup_vault_container, VaultMode};
use log::{error, info};
use merka_vault::actor::{self, InitVault, VaultEvent};
use merka_vault::vault::{autounseal, transit};
use std::time::Duration;

/// Demonstrates passing an **unwrapped** token (rather than root) to the target Vault’s
/// auto-unseal configuration in a more realistic flow:
///
/// 1) Spin up the “unsealer” vault in `Regular` mode.
/// 2) Init & unseal it (using the actor for init).
/// 3) Enable Transit & create an encryption key. Then **generate a wrapped token** (with minimal policy).
/// 4) **Unwrap** that token on the “unsealer” side – retrieving the real client token.
/// 5) Spin up the target Vault in `VaultMode::AutoUnseal`, passing that **unwrapped** token,
///    so it can immediately talk to the unsealer’s transit engine on startup.
/// 6) Call `init_with_autounseal` – the target sets up recovery keys & auto-unseals automatically.
#[actix_rt::test]
async fn test_auto_unseal_with_unwrapped_token() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    // --- 1) Spin up “unsealer” vault in Regular mode ---
    let unsealer_container = setup_vault_container(VaultMode::Regular).await;
    let unsealer_host = unsealer_container.get_host().await?;
    let unsealer_port = unsealer_container.get_host_port_ipv4(8200).await?;
    let unsealer_url = format!("http://{}:{}", unsealer_host, unsealer_port);
    info!("Unsealer vault at: {unsealer_url}");

    sleep(Duration::from_secs(3)).await;

    // Start an actor for the unsealer vault & init it
    let (unsealer_addr, mut unsealer_rx) = actor::start_vault_actor_with_channel(&unsealer_url);
    unsealer_addr
        .send(InitVault {
            secret_shares: 1,
            secret_threshold: 1,
        })
        .await??; // Double question mark to handle both the send result and the inner result

    // Wait for the "Initialized" event
    let unsealer_event = timeout(Duration::from_secs(15), unsealer_rx.recv()).await;
    let mut unsealer_root_token = None;
    let mut unsealer_keys = Vec::new();

    match unsealer_event {
        Ok(Ok(VaultEvent::Initialized { root_token, keys })) => {
            info!("Unsealer vault initialized, root_token={root_token}");
            unsealer_root_token = Some(root_token);
            unsealer_keys = keys;
        }
        Ok(Ok(VaultEvent::Error(e))) => {
            error!("Unsealer init error: {}", e);
            return Err(format!("Unsealer init error: {e}").into());
        }
        other => {
            error!("Unexpected unsealer event: {:?}", other);
            return Err("Unexpected unsealer event".into());
        }
    }

    // Unseal the unsealer vault with the returned key
    if let Some(k) = unsealer_keys.first() {
        let resp = reqwest::Client::new()
            .put(format!("{}/v1/sys/unseal", unsealer_url))
            .json(&serde_json::json!({ "key": k }))
            .send()
            .await?;
        if resp.status().is_success() {
            info!("Unsealer vault is now unsealed");
        } else {
            let body = resp.text().await?;
            return Err(format!("Failed to unseal unsealer vault: {body}").into());
        }
    }

    // --- 2) Set up transit + create a minimal policy. We want a limited permissions token. ---
    let unsealer_token = unsealer_root_token.as_ref().ok_or("No unsealer token")?;
    let transit_key_name = "auto-unseal-key";
    autounseal::setup_transit_autounseal(&unsealer_url, unsealer_token, transit_key_name).await?;
    info!("Transit engine ready on unsealer vault: key={transit_key_name}");

    // --- 3) Generate a **wrapped** token (short-lived). We'll then unwrap it. ---
    let policy_name = "autounseal"; // from setup_transit_autounseal
    let wrap_ttl = "300s"; // 5 minutes
    let wrapped_token = transit::generate_wrapped_transit_token(
        &unsealer_url,
        unsealer_token,
        policy_name,
        wrap_ttl,
    )
    .await?;
    info!("Wrapped token (response-wrapped): {wrapped_token}");

    // --- 4) **Unwrap** that token right away (on the unsealer side) -> real client token
    let real_client_token = autounseal::unwrap_token(&unsealer_url, &wrapped_token).await?;
    info!("Unwrapped client token = {real_client_token}");

    // --- 5) Spin up the target in `AutoUnseal` mode, passing the *unwrapped* token ---
    let unsealer_bridge_ip = unsealer_container.get_bridge_ip_address().await?;
    let target_container = setup_vault_container(VaultMode::AutoUnseal {
        unsealer_url: format!("http://{}:8200", unsealer_bridge_ip),
        token: real_client_token.clone(), // <--- pass the *actual* unwrapped token!
        key_name: transit_key_name.to_string(),
    })
    .await;

    sleep(Duration::from_secs(3)).await;

    let target_host = target_container.get_host().await?;
    let target_port = target_container.get_host_port_ipv4(8200).await?;
    let target_url = format!("http://{}:{}", target_host, target_port);
    info!("Target vault in auto-unseal mode at: {target_url}");

    // --- 6) Call init_with_autounseal, verifying it can talk to unsealer’s transit with that token
    match autounseal::init_with_autounseal(&target_url).await {
        Ok(init_result) => {
            info!("Target auto-unseal init success: {:?}", init_result);

            // Check if the target is sealed
            let status_resp = reqwest::Client::new()
                .get(format!("{}/v1/sys/seal-status", &target_url))
                .send()
                .await?;
            let status_json = status_resp.json::<serde_json::Value>().await?;
            info!("Target seal-status: {status_json:#?}");
            if status_json["sealed"] == false {
                info!("Success! Target is unsealed automatically using unwrapped token!");
            } else {
                error!("Target is still sealed? Something went wrong.");
            }
        }
        Err(e) => {
            error!("Auto-unseal init failed: {e}");
            return Err(e.into());
        }
    }

    Ok(())
}
