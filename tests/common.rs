//! Common test fixtures for Vault integration tests.
//!
//! This module starts a HashiCorp Vault container in dev mode only once.
//! It uses Testcontainers 0.23 to run the container with a fixed root token (`"root"`)
//! and maps container port 8200 to host port 8200. This container is shared across all
//! integration tests. To run these tests, set the environment variable
//! `MERKA_VAULT_RUN_INTEGRATION_TESTS=true`.

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

pub struct VaultFixture {
    container: ContainerAsync<GenericImage>,
    vault_addr: String,
}

impl VaultFixture {
    pub async fn new() -> Self {
        let container = GenericImage::new("hashicorp/vault", "1.18.4")
            .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .with_cmd(vec!["server", "-dev", "-dev-root-token-id=root"])
            .with_mapped_port(8200, 8200.tcp())
            .start()
            .await
            .unwrap();

        let vault_addr = format!("http://127.0.0.1:8200");

        VaultFixture {
            container,
            vault_addr,
        }
    }

    pub fn vault_addr(&self) -> String {
        self.vault_addr.clone()
    }
}
