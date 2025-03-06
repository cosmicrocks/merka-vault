// tests/actor_integration.rs

use actix::Actor;
use merka_vault::actor::{InitVault, VaultActor};
use tokio::time::{sleep, Duration};

mod common;

#[actix_rt::test]
async fn test_actor_init_message() -> Result<(), Box<dyn std::error::Error>> {
    // Start a Vault container using your common helper.
    let vault_container = common::setup_vault_container(common::VaultMode::Regular).await;
    let host = vault_container.get_host().await.unwrap();
    let port = vault_container.get_host_port_ipv4(8200).await.unwrap();
    let vault_url = format!("http://{}:{}", host, port);

    // Create the VaultActor with the Vault URL from the container.
    let vault_actor_addr = VaultActor::new(vault_url).start();

    // Send an InitVault message to the actor.
    let init_msg = InitVault {
        secret_shares: 5,
        secret_threshold: 3,
    };

    // Send the message and wait for the actor to respond.
    let res = vault_actor_addr.send(init_msg).await?;
    assert!(res.is_ok());
    let keys = res.unwrap().keys;
    assert_eq!(keys.len(), 5);

    // Sleep for a bit to allow the actor to finish its work.
    sleep(Duration::from_secs(1)).await;

    // Stop the Vault container.
    vault_container.stop().await?;

    Ok(())
}
