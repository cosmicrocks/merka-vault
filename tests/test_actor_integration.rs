//! tests/test_actor_integration.rs

mod common;
use actix_rt::time::timeout;
use common::{init_logging, setup_vault_container, VaultMode};
use merka_vault::actor::{
    self, ActorError, AddUnsealerRelationship, AutoUnseal, CheckDependencies, CheckStatus,
    GenerateWrappedToken, GetCurrentAddress, InitVault, RegisterVault, SealVault,
    SetCurrentAddress, SetupRoot, SetupSub, SetupTransit, UnsealVault, UnwrapToken, VaultEvent,
    VerifyTokenPermissions,
};
use std::time::Duration;
use tracing::{error, info};

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
    tokio::time::sleep(startup_wait).await;

    // --- STAGE 2: Initialize and unseal the vault with an actor ---
    info!("STAGE 2: Initializing unsealer vault via actor");
    let (unsealer_addr, mut unsealer_rx) = actor::start_vault_actor_with_channel(&unsealer_url);

    // Send initialization message
    let init_msg = InitVault {
        secret_shares: 1,
        secret_threshold: 1,
    };

    match unsealer_addr.send(init_msg).await {
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
        // Replace direct reqwest unseal call with actor message
        match unsealer_addr
            .send(UnsealVault {
                keys: vec![unseal_key.clone()],
            })
            .await
        {
            Ok(Ok(unseal_result)) => {
                if !unseal_result.sealed {
                    info!("✅ Unsealer vault unsealed successfully");
                } else {
                    return Err(
                        "Unsealer vault reports it's still sealed after unseal operation".into(),
                    );
                }
            }
            Ok(Err(e)) => return Err(format!("Failed to unseal vault: {e}").into()),
            Err(e) => {
                return Err(format!("Failed to send UnsealVault message to actor: {e}").into())
            }
        }

        // Verify unsealed status with status check via actor
        match unsealer_addr.send(CheckStatus).await {
            Ok(Ok(status)) => {
                if status.sealed {
                    return Err(
                        "Unsealer vault reports it's still sealed after unseal operation".into(),
                    );
                }
                info!(
                    "✅ Confirmed unseal with status check: sealed={}",
                    status.sealed
                );
            }
            Ok(Err(e)) => return Err(format!("Failed to check vault status: {e}").into()),
            Err(e) => {
                return Err(format!("Failed to send CheckStatus message to actor: {e}").into())
            }
        }
    } else {
        return Err("No unseal keys received from initialization".into());
    }

    // --- STAGE 3: Set up transit engine + create minimal policy ---
    info!("STAGE 3: Setting up transit engine for auto-unseal");
    let transit_key_name = "auto-unseal-key";

    // Instead of calling autounseal::setup_transit_autounseal directly,
    // use the actor pattern with SetupTransit message
    match unsealer_addr
        .send(SetupTransit {
            key_name: transit_key_name.to_string(),
            token: unsealer_root_token.clone(), // Pass the root token
        })
        .await
    {
        Ok(Ok(_)) => {
            info!("✅ Transit engine configured successfully with key: {transit_key_name}")
        }
        Ok(Err(e)) => return Err(format!("Actor failed to setup transit auto-unseal: {e}").into()),
        Err(e) => return Err(format!("Failed to send SetupTransit message to actor: {e}").into()),
    }

    // --- STAGE 4: Generate wrapped token and unwrap it ---
    info!("STAGE 4: Generating and unwrapping a transit token");
    let policy_name = "autounseal"; // Created by setup_transit_autounseal
    let wrap_ttl = "300s"; // 5 minutes TTL for the wrapped token

    // Generate wrapped token using the actor interface
    let wrapped_token = match unsealer_addr
        .send(GenerateWrappedToken {
            policy_name: policy_name.to_string(),
            wrap_ttl: wrap_ttl.to_string(),
            token: unsealer_root_token.clone(), // Pass the root token
        })
        .await
    {
        Ok(Ok(token)) => {
            info!("✅ Generated wrapped token successfully");
            token
        }
        Ok(Err(e)) => return Err(format!("Actor failed to generate wrapped token: {e}").into()),
        Err(e) => {
            return Err(format!("Failed to send GenerateWrappedToken message to actor: {e}").into())
        }
    };

    // Unwrap the token using the actor interface
    let real_client_token = match unsealer_addr
        .send(UnwrapToken {
            wrapped_token: wrapped_token.clone(),
        })
        .await
    {
        Ok(Ok(token)) => {
            info!("✅ Successfully unwrapped token");
            token
        }
        Ok(Err(e)) => return Err(format!("Actor failed to unwrap token: {e}").into()),
        Err(e) => return Err(format!("Failed to send UnwrapToken message to actor: {e}").into()),
    };

    // Verify token has correct permissions by testing a simple encrypt operation
    info!("Verifying token permissions...");
    // Instead of direct encrypt call, use the actor to verify token permissions
    match unsealer_addr
        .send(VerifyTokenPermissions {
            token: real_client_token.clone(),
            key_name: transit_key_name.to_string(),
        })
        .await
    {
        Ok(Ok(_)) => info!("✅ Token permissions verified successfully"),
        Ok(Err(e)) => return Err(format!("Token permission verification failed: {e}").into()),
        Err(e) => {
            return Err(
                format!("Failed to send VerifyTokenPermissions message to actor: {e}").into(),
            )
        }
    }

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

    // Wait for the target vault to be ready
    info!("Waiting for target vault to be available...");
    let target_url = format!(
        "http://{}:{}",
        target_container.get_host().await?,
        target_container.get_host_port_ipv4(8200).await?
    );
    common::wait_for_vault_ready(&target_url, 10, 1000).await?;

    let target_host = target_container.get_host().await?;
    let target_port = target_container.get_host_port_ipv4(8200).await?;
    let target_url = format!("http://{}:{}", target_host, target_port);
    info!("Target vault running at: {target_url}");

    // --- STAGE 6: Initialize with auto-unseal and verify it works ---
    info!("STAGE 6: Initializing target vault with auto-unseal");

    // Use the actor for the target vault too
    let (target_addr, mut target_rx) = actor::start_vault_actor_with_channel(&target_url);

    // Initialize with timeout since this operation can sometimes take longer
    let init_timeout = Duration::from_secs(30);

    // Send auto-unseal message
    let auto_unseal_result = timeout(init_timeout, async {
        // Use the actor's AutoUnseal message
        match target_addr.send(AutoUnseal {}).await {
            Ok(result) => result,
            Err(e) => Err(ActorError::VaultApi(format!(
                "Failed to send AutoUnseal message: {e}"
            ))),
        }
    })
    .await;

    let _auto_unseal_result = match auto_unseal_result {
        Ok(Ok(result)) => {
            info!("✅ Target auto-unseal initialization succeeded via actor");
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

    // Wait for the AutounsealComplete event to confirm the operation
    let event_wait_timeout = Duration::from_secs(5);
    let _ = timeout(event_wait_timeout, async {
        loop {
            match target_rx.recv().await {
                Ok(VaultEvent::AutounsealComplete {
                    root_token: _,
                    recovery_keys,
                }) => {
                    info!(
                        "✅ Received AutounsealComplete event with {} recovery keys",
                        recovery_keys.as_ref().map_or(0, |keys| keys.len())
                    );
                    break;
                }
                Ok(event) => {
                    info!(
                        "Received event while waiting for AutounsealComplete: {:?}",
                        event
                    );
                }
                Err(e) => {
                    error!("❌ Failed to receive event: {}", e);
                    break;
                }
            }
        }
    })
    .await;

    // Verify token is valid by making a simple API call
    info!("Verifying root token from auto-unsealed vault...");
    // Use the actor instead of direct API call - the token is stored in the actor instance
    match target_addr.send(CheckStatus).await {
        Ok(Ok(_)) => info!("✅ Root token verified successfully"),
        Ok(Err(e)) => return Err(format!("Root token verification failed: {e}").into()),
        Err(e) => return Err(format!("Failed to send CheckStatus message to actor: {e}").into()),
    }

    // Verify the target vault is unsealed
    info!("Checking seal status of target vault...");
    // Use the actor's CheckStatus instead of direct API call
    let status = match target_addr.send(CheckStatus).await {
        Ok(Ok(s)) => {
            info!(
                "Target seal status: initialized={}, sealed={}, standby={}",
                s.initialized, s.sealed, s.standby
            );
            s
        }
        Ok(Err(e)) => return Err(format!("Failed to check seal status: {e}").into()),
        Err(e) => return Err(format!("Failed to send CheckStatus message to actor: {e}").into()),
    };

    // Assertions to verify test success
    assert!(
        !status.sealed,
        "Target vault is still sealed after auto-unseal"
    );
    assert!(status.initialized, "Target vault is not initialized");

    info!("✅ SUCCESS: Target vault is initialized and auto-unsealed using real unwrapped token!");

    // Cleanup if needed - in real use you might want to delete containers
    // This is optional as testcontainers automatically cleans up

    Ok(())
}

/// Tests the auto-unseal dependency monitoring functionality of the VaultActor.
/// This test verifies that the actor properly detects and reports issues with
/// auto-unseal dependencies, particularly when the root vault becomes sealed
/// while the sub vault remains unsealed.
///
/// The test follows these steps:
/// 1. Set up a root vault in regular mode
/// 2. Set up a sub vault with auto-unseal configured to use the root vault
/// 3. Seal the root vault (using the actor)
/// 4. Check that the actor detects the auto-unseal dependency issue and emits
///    an appropriate error event
#[actix_rt::test]
async fn test_auto_unseal_dependency_monitoring() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    // --- STAGE 1: Set up root vault in regular mode ---
    info!("STAGE 1: Starting unsealer (root) vault in Regular mode");
    let root_container = setup_vault_container(VaultMode::Regular).await;
    let root_host = root_container.get_host().await?;
    let root_port = root_container.get_host_port_ipv4(8200).await?;
    let root_addr = format!("http://{}:{}", root_host, root_port);

    // Wait for container to be ready
    info!("Waiting for root Vault to be available...");
    common::wait_for_vault_ready(&root_addr, 10, 1000).await?;

    // Start actor with monitoring enabled
    let (actor, mut rx) = actor::start_vault_actor_with_channel(&root_addr);

    // --- STAGE 2: Set up root vault using the actor ---
    info!("STAGE 2: Setting up root vault...");
    let setup_result = actor
        .send(SetupRoot {
            addr: root_addr.clone(),
            secret_shares: 1,
            secret_threshold: 1,
            key_name: "test-key".to_string(),
        })
        .await??;

    info!("Root setup completed, unwrapped token: {}", setup_result);
    let unwrapped_token = setup_result;

    // Wait for the Initialized event to get the root token
    let mut root_token = None;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout && root_token.is_none() {
        match rx.try_recv() {
            Ok(VaultEvent::Initialized { root_token: rt, .. }) => {
                root_token = Some(rt);
                break;
            }
            Ok(_) => {}
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }

    let admin_token = root_token.ok_or("Failed to capture root token from event")?;
    info!("Captured admin token: {}", admin_token);

    // Get root vault's internal address for container-to-container communication
    let root_internal_host = root_container.get_bridge_ip_address().await?;
    let root_internal_url = format!("http://{}:8200", root_internal_host);

    // --- STAGE 3: Start sub vault container with auto-unseal ---
    info!("STAGE 3: Starting sub vault with auto-unseal configuration");
    let sub_container = setup_vault_container(VaultMode::AutoUnseal {
        transit_unseal_url: root_internal_url,
        token: unwrapped_token.clone(),
        key_name: "test-key".to_string(),
    })
    .await;

    let sub_host = sub_container.get_host().await?;
    let sub_port = sub_container.get_host_port_ipv4(8200).await?;
    let sub_addr = format!("http://{}:{}", sub_host, sub_port);
    info!("Sub vault running at: {}", sub_addr);

    // --- STAGE 4: Setup sub vault using the actor ---
    info!("STAGE 4: Setting up sub vault...");
    actor
        .send(SetupSub {
            root_addr: root_addr.clone(),
            root_token: admin_token.clone(),
            sub_addr: sub_addr.clone(),
            domain: "example.com".to_string(),
            ttl: "87600h".to_string(),
        })
        .await??;

    // Give the system time to detect the relationship
    info!("Waiting for relationship to be detected...");
    common::wait_for_vault_ready(&sub_addr, 5, 500).await?;

    // --- STAGE 5: Register vaults and relationship with actor ---
    info!("STAGE 5: Registering vaults and relationship with actor");

    // Register both vaults with the actor
    info!("Registering root vault: {}", root_addr);
    actor.send(RegisterVault(root_addr.clone())).await??;

    info!("Registering sub vault: {}", sub_addr);
    actor.send(RegisterVault(sub_addr.clone())).await??;

    // Register the relationship between them
    info!(
        "Registering unsealer relationship: sub={} -> root={}",
        sub_addr, root_addr
    );
    actor
        .send(AddUnsealerRelationship {
            sub_addr: sub_addr.clone(),
            root_addr: root_addr.clone(),
        })
        .await??;

    // Drain events that might have accumulated
    info!("Draining existing events from channel");
    while rx.try_recv().is_ok() {
        // Just discard any events that might be in the channel
    }

    // --- STAGE 6: Seal the root vault ---
    info!("STAGE 6: Sealing root vault to test dependency monitoring");

    // Store the original address and switch the actor to target the root vault
    let original_addr = actor.send(GetCurrentAddress).await??;
    info!("Original vault address: {}", original_addr);

    // Switch to root vault
    info!("Switching actor to target root vault: {}", root_addr);
    actor.send(SetCurrentAddress(root_addr.clone())).await??;

    // Seal the root vault using actor
    info!("Sealing root vault with token: {}", admin_token);
    actor
        .send(SealVault {
            token: admin_token.clone(),
        })
        .await??;

    // Verify root vault is sealed
    info!("Checking root vault status after sealing");
    let root_status = actor.send(CheckStatus).await??;
    info!(
        "Root vault status: sealed={}, initialized={}",
        root_status.sealed, root_status.initialized
    );

    // Verify root is actually sealed
    assert!(
        root_status.sealed,
        "Root vault should be sealed for this test"
    );

    // Switch back to original address before continuing
    info!("Switching back to original address: {}", original_addr);
    actor
        .send(SetCurrentAddress(original_addr.clone()))
        .await??;

    // Give time for the sealing to take effect
    info!("Waiting for sealing to take effect");
    // We intentionally sealed the root vault, so don't wait for it to be "ready" (unsealed)
    // Instead, just give the system a moment to register the sealed state
    tokio::time::sleep(Duration::from_secs(2)).await;

    // --- STAGE 7: Check dependency status ---
    info!("STAGE 7: Checking dependency status");

    // Trigger dependency check with actor pointing to original address
    info!("Triggering dependency check");
    actor.send(CheckDependencies).await??;

    // To check sub vault status, switch to sub vault
    info!("Switching to sub vault to check its status: {}", sub_addr);
    actor.send(SetCurrentAddress(sub_addr.clone())).await??;
    let sub_status = actor.send(CheckStatus).await??;
    info!(
        "Sub vault status: sealed={}, initialized={}",
        sub_status.sealed, sub_status.initialized
    );

    // Finally restore the original address
    info!("Switching back to original address: {}", original_addr);
    actor
        .send(SetCurrentAddress(original_addr.clone()))
        .await??;

    // --- STAGE 8: Wait for dependency error event ---
    info!("STAGE 8: Waiting for dependency error events");

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(10); // Extend timeout for more reliability
    let mut dependency_error_received = false;

    info!(
        "Starting event loop, will check for events for up to {} seconds",
        timeout.as_secs()
    );
    while start.elapsed() < timeout && !dependency_error_received {
        match rx.try_recv() {
            Ok(event) => {
                info!("Received event: {:?}", event);
                match event {
                    VaultEvent::AutoUnsealDependencyError {
                        sub_addr: event_sub_addr,
                        root_addr: event_root_addr,
                        error,
                    } => {
                        info!(
                            "✅ Received AutoUnsealDependencyError event! Error: {}",
                            error
                        );
                        assert_eq!(
                            event_sub_addr, sub_addr,
                            "Sub address in event should match"
                        );
                        assert_eq!(
                            event_root_addr, root_addr,
                            "Root address in event should match"
                        );
                        dependency_error_received = true;
                    }
                    _ => {
                        info!("Received other event: {:?}", event);
                    }
                }
            }
            Err(_) => {
                // No events available, wait a bit
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    // Log outcome
    if dependency_error_received {
        info!("Successfully received dependency error event");
    } else {
        error!("Did not receive dependency error event within timeout period");
    }

    assert!(
        dependency_error_received,
        "Should have received AutoUnsealDependencyError event"
    );

    info!("✅ Auto-unseal dependency monitoring test completed successfully");

    Ok(())
}
