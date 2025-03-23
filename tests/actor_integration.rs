//! tests/actor_integration.rs

mod common;
use actix_rt::time::{sleep, timeout};
use common::{init_logging, setup_vault_container, VaultMode};
use log::{error, info};
use merka_vault::actor::{self, InitVault, VaultEvent};
use merka_vault::vault::{autounseal, transit};
use std::time::Duration;

/// Demonstrates passing an **unwrapped** token (rather than root) to the target Vault's
/// auto-unseal configuration in a more realistic flow:
///
/// 1) Spin up the "unsealer" vault in `Regular` mode.
/// 2) Init & unseal it (using the actor for init).
/// 3) Enable Transit & create an encryption key. Then **generate a wrapped token** (with minimal policy).
/// 4) **Unwrap** that token on the "unsealer" side – retrieving the real client token.
/// 5) Spin up the target Vault in `VaultMode::AutoUnseal`, passing that **unwrapped** token,
///    so it can immediately talk to the unsealer's transit engine on startup.
/// 6) Call `init_with_autounseal` – the target sets up recovery keys & auto-unseals automatically.
#[actix_rt::test]
async fn test_auto_unseal_with_unwrapped_token() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    // --- STAGE 1: Spin up "unsealer" vault in Regular mode ---
    info!("STAGE 1: Starting unsealer vault in Regular mode");
    let unsealer_container = setup_vault_container(VaultMode::Regular).await;
    let unsealer_host = unsealer_container.get_host().await?;
    let unsealer_port = unsealer_container.get_host_port_ipv4(8200).await?;
    let unsealer_url = format!("http://{}:{}", unsealer_host, unsealer_port);
    info!("Unsealer vault running at: {unsealer_url}");

    // Wait for the unsealer vault to fully start
    let startup_wait = Duration::from_secs(3);
    info!(
        "Waiting {}s for unsealer vault to initialize...",
        startup_wait.as_secs()
    );
    sleep(startup_wait).await;

    // --- STAGE 2: Initialize and unseal the vault with an actor ---
    info!("STAGE 2: Initializing unsealer vault via actor");
    let (unsealer_addr, mut unsealer_rx) = actor::start_vault_actor_with_channel(&unsealer_url);

    // Send initialization message
    let init_msg = InitVault {
        secret_shares: 1,
        secret_threshold: 1,
    };

    let _ = match unsealer_addr.send(init_msg).await {
        Ok(result) => match result {
            Ok(_) => {
                info!("Actor successfully processed InitVault message");
            }
            Err(e) => return Err(format!("Actor failed to process InitVault message: {e}").into()),
        },
        Err(e) => return Err(format!("Failed to send InitVault message to actor: {e}").into()),
    };

    // Monitor events from the actor with timeout
    info!("Waiting for vault initialization events...");
    let overall_timeout = Duration::from_secs(30);
    let init_result = timeout(overall_timeout, async {
        loop {
            match unsealer_rx.recv().await {
                Ok(VaultEvent::Initialized { root_token: token, keys: vault_keys }) => {
                    info!("✅ Unsealer vault initialized successfully");
                    return Ok((token, vault_keys));
                }
                Ok(VaultEvent::StatusChecked { initialized, sealed, standby }) => {
                    info!("Vault status update: initialized={initialized}, sealed={sealed}, standby={standby}");
                }
                Ok(VaultEvent::Error(e)) => {
                    error!("❌ Unsealer initialization error: {}", e);
                    return Err(format!("Unsealer init error: {e}"));
                }
                Ok(event) => {
                    info!("Received event: {:?}", event);
                }
                Err(e) => {
                    error!("❌ Failed to receive event: {}", e);
                    return Err(format!("Failed to receive event: {e}"));
                }
            }
        }
    }).await;

    let (unsealer_root_token, unsealer_keys) = match init_result {
        Ok(Ok((token, keys))) => (token, keys),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("Timed out waiting for vault initialization".into()),
    };

    // Unseal the unsealer vault with the returned key
    info!("Unsealing the unsealer vault...");
    if let Some(unseal_key) = unsealer_keys.first() {
        let client = reqwest::Client::new();
        let resp = client
            .put(format!("{}/v1/sys/unseal", unsealer_url))
            .json(&serde_json::json!({ "key": unseal_key }))
            .send()
            .await?;

        if resp.status().is_success() {
            info!("✅ Unsealer vault unsealed successfully");

            // Verify unsealed status with an additional check
            let status_resp = client
                .get(format!("{}/v1/sys/seal-status", unsealer_url))
                .send()
                .await?;

            let status = status_resp.json::<serde_json::Value>().await?;
            if status["sealed"].as_bool().unwrap_or(true) {
                return Err(
                    "Unsealer vault reports it's still sealed after unseal operation".into(),
                );
            }
        } else {
            let body = resp.text().await?;
            return Err(format!("Failed to unseal unsealer vault: {body}").into());
        }
    } else {
        return Err("No unseal keys received from initialization".into());
    }

    // --- STAGE 3: Set up transit engine + create minimal policy ---
    info!("STAGE 3: Setting up transit engine for auto-unseal");
    let transit_key_name = "auto-unseal-key";
    match autounseal::setup_transit_autounseal(
        &unsealer_url,
        &unsealer_root_token,
        transit_key_name,
    )
    .await
    {
        Ok(_) => info!("✅ Transit engine configured successfully with key: {transit_key_name}"),
        Err(e) => return Err(format!("Failed to setup transit auto-unseal: {e}").into()),
    }

    // --- STAGE 4: Generate wrapped token and unwrap it ---
    info!("STAGE 4: Generating and unwrapping a transit token");
    let policy_name = "autounseal"; // Created by setup_transit_autounseal
    let wrap_ttl = "300s"; // 5 minutes TTL for the wrapped token

    // Generate wrapped token
    let wrapped_token = match transit::generate_wrapped_transit_token(
        &unsealer_url,
        &unsealer_root_token,
        policy_name,
        wrap_ttl,
    )
    .await
    {
        Ok(token) => {
            info!("✅ Generated wrapped token successfully");
            token
        }
        Err(e) => return Err(format!("Failed to generate wrapped token: {e}").into()),
    };

    // Unwrap the token to get the actual client token
    let real_client_token = match autounseal::unwrap_token(&unsealer_url, &wrapped_token).await {
        Ok(token) => {
            info!("✅ Successfully unwrapped token");
            token
        }
        Err(e) => return Err(format!("Failed to unwrap token: {e}").into()),
    };

    // Verify token has correct permissions by testing a simple encrypt operation
    info!("Verifying token permissions...");
    let client = reqwest::Client::new();
    let encrypt_resp = client
        .post(format!(
            "{}/v1/transit/encrypt/{}",
            unsealer_url, transit_key_name
        ))
        .header("X-Vault-Token", &real_client_token)
        .json(&serde_json::json!({
            "plaintext": "dGVzdA==" // Base64 encoded "test"
        }))
        .send()
        .await?;

    if !encrypt_resp.status().is_success() {
        let body = encrypt_resp.text().await?;
        return Err(format!("Token permission verification failed: {body}").into());
    }
    info!("✅ Token permissions verified successfully");

    // --- STAGE 5: Spin up target vault in AutoUnseal mode with unwrapped token ---
    info!("STAGE 5: Starting target vault in AutoUnseal mode");
    let unsealer_bridge_ip = unsealer_container.get_bridge_ip_address().await?;
    let transit_unsealer_url = format!("http://{}:8200", unsealer_bridge_ip);

    info!("Configuring target vault with unsealer at {transit_unsealer_url}");
    let target_container = setup_vault_container(VaultMode::AutoUnseal {
        transit_unseal_url: transit_unsealer_url.clone(),
        token: real_client_token.clone(), // Pass the unwrapped token
        key_name: transit_key_name.to_string(),
    })
    .await;

    let startup_wait = Duration::from_secs(5);
    info!(
        "Waiting {}s for target vault to start...",
        startup_wait.as_secs()
    );
    sleep(startup_wait).await;

    let target_host = target_container.get_host().await?;
    let target_port = target_container.get_host_port_ipv4(8200).await?;
    let target_url = format!("http://{}:{}", target_host, target_port);
    info!("Target vault running at: {target_url}");

    // --- STAGE 6: Initialize with auto-unseal and verify it works ---
    info!("STAGE 6: Initializing target vault with auto-unseal");

    // Initialize with timeout since this operation can sometimes take longer
    let init_timeout = Duration::from_secs(30);
    let auto_unseal_result = timeout(init_timeout, async {
        autounseal::init_with_autounseal(&target_url).await
    })
    .await;

    let init_result = match auto_unseal_result {
        Ok(Ok(result)) => {
            info!("✅ Target auto-unseal initialization succeeded");
            info!("  - Root token: {}", result.root_token);
            info!(
                "  - Recovery keys: {} keys received",
                result.recovery_keys.as_ref().map_or(0, |keys| keys.len())
            );
            result
        }
        Ok(Err(e)) => return Err(format!("Auto-unseal initialization failed: {e}").into()),
        Err(_) => return Err("Auto-unseal initialization timed out".into()),
    };

    // Verify token is valid by making a simple API call
    info!("Verifying root token from auto-unsealed vault...");
    let token_verification = reqwest::Client::new()
        .get(format!("{}/v1/sys/health", target_url))
        .header("X-Vault-Token", &init_result.root_token)
        .send()
        .await?;

    if !token_verification.status().is_success() {
        return Err("Root token from auto-unsealed vault failed verification".into());
    }
    info!("✅ Root token verified successfully");

    // Verify the target vault is unsealed
    info!("Checking seal status of target vault...");
    let status_resp = reqwest::Client::new()
        .get(format!("{}/v1/sys/seal-status", &target_url))
        .send()
        .await?;

    let status_json = status_resp.json::<serde_json::Value>().await?;
    info!(
        "Target seal-status: {}",
        serde_json::to_string_pretty(&status_json)?
    );

    // Assertions to verify test success
    assert!(
        !status_json["sealed"].as_bool().unwrap_or(true),
        "Target vault is still sealed after auto-unseal"
    );
    assert!(
        status_json["initialized"].as_bool().unwrap_or(false),
        "Target vault is not initialized"
    );

    info!("✅ SUCCESS: Target vault is initialized and auto-unsealed using real unwrapped token!");

    // Cleanup if needed - in real use you might want to delete containers
    // This is optional as testcontainers automatically cleans up

    Ok(())
}
