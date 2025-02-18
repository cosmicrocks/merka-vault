// tests/actor_integration.rs

use actix::Actor;
use merka_vault::actor::{InitVault, VaultActor};
use tokio::time::{sleep, Duration};

mod common;

#[actix_rt::test]
async fn test_actor_init_message() -> Result<(), Box<dyn std::error::Error>> {
    // Start a Vault dev container using your common helper.
    let vault_container = common::setup_vault_dev_container().await;
    let host = vault_container.get_host().await.unwrap();
    let port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, port);

    // Create the VaultActor with the Vault URL from the container.
    let vault_actor_addr = VaultActor::new(vault_url).start();

    // Send an InitVault message to the actor.
    let init_msg = InitVault {
        secret_shares: 1,
        secret_threshold: 1,
    };

    // Since the dev container is already initialized, we expect the init to fail.
    let result = vault_actor_addr.send(init_msg).await?;
    assert!(
        result.is_err(),
        "Expected Vault initialization to fail on a dev container, but got an Ok result"
    );

    // Optionally, print the error for debugging.
    if let Err(err) = result {
        println!("Received expected error: {}", err);
    }

    // Wait a bit before test completion.
    sleep(Duration::from_secs(1)).await;

    Ok(())
}
