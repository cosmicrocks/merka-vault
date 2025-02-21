use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

pub enum VaultMode {
    // TODO: understand why this is needed, Regular is being used in the tests
    #[allow(dead_code)]
    Regular,
    Dev,
}

pub async fn setup_vault_container(mode: VaultMode) -> ContainerAsync<GenericImage> {
    match mode {
        VaultMode::Dev => GenericImage::new("hashicorp/vault", "1.18.4")
            .with_exposed_port(8200.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
            .with_network("bridge")
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .with_cmd(vec!["server", "-dev", "-dev-root-token-id=root"])
            .start()
            .await
            .unwrap(),
        VaultMode::Regular => {
            let vault_local_config = r#"
            {"storage": {"file": {"path": "/vault/file"}},
             "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}],
             "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}
            "#;
            GenericImage::new("hashicorp/vault", "1.18.4")
                .with_exposed_port(8200.tcp())
                .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
                .with_network("bridge")
                .with_env_var("VAULT_LOCAL_CONFIG", vault_local_config)
                .with_cmd(vec!["server"])
                .with_cap_add("IPC_LOCK")
                .start()
                .await
                .unwrap()
        }
    }
}
