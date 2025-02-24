//! actor.rs – Actor integration for Vault operations.

use crate::vault;
use actix::prelude::*;
use futures_util::FutureExt;

/// Actor that manages Vault operations.
pub struct VaultActor {
    pub vault_addr: String,
    pub root_token: Option<String>,
}

impl VaultActor {
    pub fn new(vault_addr: impl Into<String>) -> Self {
        Self {
            vault_addr: vault_addr.into(),
            root_token: None,
        }
    }
}

/// Message for initializing Vault.
#[derive(Message)]
#[rtype(result = "Result<InitResult, vault::VaultError>")]
pub struct InitVault {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

/// Message for unsealing Vault.
#[derive(Message)]
#[rtype(result = "Result<(), vault::VaultError>")]
pub struct UnsealVault {
    pub keys: Vec<String>,
}

/// Message for setting up the PKI engine.
#[derive(Message)]
#[rtype(result = "Result<PkiResult, vault::VaultError>")]
pub struct SetupPki {
    pub common_name: String,
    pub ttl: String,
    pub use_intermediate: bool,
    pub intermediate_addr: Option<String>,
    pub int_token: Option<String>,
}

/// Message for setting up AppRole authentication.
#[derive(Message)]
#[rtype(result = "Result<AppRoleCredentials, vault::VaultError>")]
pub struct SetupAppRole {
    pub role_name: String,
    pub policies: Vec<String>,
}

/// Message for setting up Kubernetes authentication.
#[derive(Message)]
#[rtype(result = "Result<(), vault::VaultError>")]
pub struct SetupKubernetes {
    pub role_name: String,
    pub service_account: String,
    pub namespace: String,
    pub kubernetes_host: String,
    pub kubernetes_ca_cert: String,
}

/// Data returned from Vault initialization.
pub struct InitResult {
    pub root_token: String,
    pub keys: Vec<String>,
}

/// Data returned from setting up PKI.
pub struct PkiResult {
    pub ca_certificate: String,
    pub role_name: String,
}

/// Data for AppRole credentials.
pub struct AppRoleCredentials {
    pub role_id: String,
    pub secret_id: String,
}

impl Actor for VaultActor {
    type Context = Context<Self>;
}

impl Handler<InitVault> for VaultActor {
    type Result = ResponseFuture<Result<InitResult, vault::VaultError>>;
    fn handle(&mut self, msg: InitVault, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        async move {
            let init_resp =
                vault::init::init_vault(&addr, msg.secret_shares, msg.secret_threshold).await?;
            Ok(InitResult {
                root_token: init_resp.root_token,
                keys: init_resp.keys,
            })
        }
        .boxed_local()
    }
}

impl Handler<UnsealVault> for VaultActor {
    type Result = ResponseFuture<Result<(), vault::VaultError>>;
    fn handle(&mut self, msg: UnsealVault, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        async move { vault::init::unseal_vault(&addr, &msg.keys).await }.boxed_local()
    }
}

impl Handler<SetupPki> for VaultActor {
    type Result = ResponseFuture<Result<PkiResult, vault::VaultError>>;
    fn handle(&mut self, msg: SetupPki, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let token = self
            .root_token
            .clone()
            .expect("Vault not initialized or unsealed");
        let common_name = msg.common_name;
        let ttl = msg.ttl;
        let use_intermediate = msg.use_intermediate;
        let int_addr = msg.intermediate_addr;
        let int_token = msg.int_token;
        async move {
            let (cert, role_name) = vault::pki::setup_pki(
                &addr,
                &token,
                &common_name,
                &ttl,
                use_intermediate,
                int_addr.as_deref(),
                int_token.as_deref(),
            )
            .await?;
            Ok(PkiResult {
                ca_certificate: cert,
                role_name,
            })
        }
        .boxed_local()
    }
}

impl Handler<SetupAppRole> for VaultActor {
    type Result = ResponseFuture<Result<AppRoleCredentials, vault::VaultError>>;
    fn handle(&mut self, msg: SetupAppRole, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let token = self
            .root_token
            .clone()
            .expect("Vault not initialized or unsealed");
        let role_name = msg.role_name;
        let policies = msg.policies;
        async move {
            let creds = vault::auth::setup_approle(&addr, &token, &role_name, &policies).await?;
            Ok(AppRoleCredentials {
                role_id: creds.role_id,
                secret_id: creds.secret_id,
            })
        }
        .boxed_local()
    }
}

impl Handler<SetupKubernetes> for VaultActor {
    type Result = ResponseFuture<Result<(), vault::VaultError>>;
    fn handle(&mut self, msg: SetupKubernetes, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let token = self
            .root_token
            .clone()
            .expect("Vault not initialized or unsealed");
        let role_name = msg.role_name;
        let service_account = msg.service_account;
        let namespace = msg.namespace;
        let kubernetes_host = msg.kubernetes_host;
        let kubernetes_ca_cert = msg.kubernetes_ca_cert;
        async move {
            vault::auth::setup_kubernetes_auth(
                &addr,
                &token,
                &role_name,
                &service_account,
                &namespace,
                &kubernetes_host,
                &kubernetes_ca_cert,
            )
            .await
        }
        .boxed_local()
    }
}
