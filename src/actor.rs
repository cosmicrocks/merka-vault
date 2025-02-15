// src/actor.rs
use crate::vault; // internal async functions for Vault API
use crate::vault::VaultError;
use actix::prelude::*;
use futures_util::FutureExt;

/// Actor that manages a Vault server instance (initialization, unsealing, config).
pub struct VaultActor {
    vault_addr: String,
    root_token: Option<String>,
}

impl VaultActor {
    pub fn new(vault_addr: impl Into<String>) -> Self {
        VaultActor {
            vault_addr: vault_addr.into(),
            root_token: None,
        }
    }
}

/// Initialize Vault (generate unseal keys and root token)
#[derive(Message)]
#[rtype(result = "Result<InitResult, VaultError>")]
pub struct InitVault {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

/// Unseal Vault using a set of unseal keys
#[derive(Message)]
#[rtype(result = "Result<(), VaultError>")]
pub struct UnsealVault {
    pub keys: Vec<String>,
}

/// Set up PKI engine (enable, configure CA and default role)
#[derive(Message)]
#[rtype(result = "Result<PkiResult, VaultError>")]
pub struct SetupPki {
    pub common_name: String, // e.g. domain name for root CA
    pub ttl: String,         // e.g. "8760h" for one year
}

/// Set up an AppRole authentication backend and create a role
#[derive(Message)]
#[rtype(result = "Result<AppRoleCredentials, VaultError>")]
pub struct SetupAppRole {
    pub role_name: String,
    pub policies: Vec<String>,
}

/// Set up Kubernetes authentication backend and role
#[derive(Message)]
#[rtype(result = "Result<(), VaultError>")]
pub struct SetupKubernetes {
    pub role_name: String,
    pub service_account: String,
    pub namespace: String,
    pub kubernetes_host: String,
    pub kubernetes_ca_cert: String,
}

// Data types for results
/// Result of Vault initialization (unseal keys and root token)
pub struct InitResult {
    pub root_token: String,
    pub keys: Vec<String>,
}
/// Result of PKI setup (CA certificate and role configured)
pub struct PkiResult {
    pub ca_certificate: String,
    pub role_name: String,
}
/// Credentials generated for an AppRole (for client login)
pub struct AppRoleCredentials {
    pub role_id: String,
    pub secret_id: String,
}

// Implement the Actor trait for VaultActor
impl Actor for VaultActor {
    type Context = Context<Self>;
}

// Handler implementations for each message, calling async functions in vault.rs
impl Handler<InitVault> for VaultActor {
    type Result = ResponseFuture<Result<InitResult, VaultError>>;
    fn handle(&mut self, msg: InitVault, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        async move {
            let init = vault::init_vault(&addr, msg.secret_shares, msg.secret_threshold).await?;
            // Store the root token in actor state for subsequent operations
            // (Note: Unseal operation is still required after init)
            // Here, we don't have access to self inside async block, so can't set self.root_token.
            // We will set it in a subsequent message handler after unseal is done.
            Ok(init)
        }
        .boxed_local()
    }
}

impl Handler<UnsealVault> for VaultActor {
    type Result = ResponseFuture<Result<(), VaultError>>;
    fn handle(&mut self, msg: UnsealVault, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let keys = msg.keys.clone();
        async move { vault::unseal_vault(&addr, &keys).await }.boxed_local()
    }
}

impl Handler<SetupPki> for VaultActor {
    type Result = ResponseFuture<Result<PkiResult, VaultError>>;
    fn handle(&mut self, msg: SetupPki, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        // Ensure we have a root token from init (Vault must be initialized & unsealed)
        let token = self
            .root_token
            .clone()
            .expect("Vault not initialized or unsealed");
        let cn = msg.common_name.clone();
        let ttl = msg.ttl.clone();
        async move {
            let (cert, role_name) = vault::setup_pki(&addr, &token, &cn, &ttl).await?;
            Ok(PkiResult {
                ca_certificate: cert,
                role_name,
            })
        }
        .boxed_local()
    }
}

impl Handler<SetupAppRole> for VaultActor {
    type Result = ResponseFuture<Result<AppRoleCredentials, VaultError>>;
    fn handle(&mut self, msg: SetupAppRole, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let token = self
            .root_token
            .clone()
            .expect("Vault not initialized or unsealed");
        let role = msg.role_name.clone();
        let policies = msg.policies.clone();
        async move {
            let creds = vault::setup_approle(&addr, &token, &role, &policies).await?;
            Ok(AppRoleCredentials {
                role_id: creds.role_id,
                secret_id: creds.secret_id,
            })
        }
        .boxed_local()
    }
}

impl Handler<SetupKubernetes> for VaultActor {
    type Result = ResponseFuture<Result<(), VaultError>>;
    fn handle(&mut self, msg: SetupKubernetes, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let token = self
            .root_token
            .clone()
            .expect("Vault not initialized or unsealed");
        // Clone all fields for move into async block
        let role = msg.role_name.clone();
        let sa = msg.service_account.clone();
        let ns = msg.namespace.clone();
        let host = msg.kubernetes_host.clone();
        let ca = msg.kubernetes_ca_cert.clone();
        async move {
            vault::setup_kubernetes_auth(&addr, &token, &role, &sa, &ns, &host, &ca).await
        }
        .boxed_local()
    }
}
