//! Integration of Vault operations with the Actix actor framework.
//!
//! This module defines the `VaultActor` which implements the `VaultOperations` trait
//! and wraps Vault functionality into Actix messages for asynchronous processing.

use crate::vault;
use crate::vault::operations::VaultOperations;
use actix::prelude::*;
use async_trait::async_trait;
use futures_util::FutureExt;

/// Actor for managing Vault operations.
pub struct VaultActor {
    pub vault_addr: String,
    pub root_token: Option<String>,
}

impl VaultActor {
    /// Constructs a new VaultActor with the given Vault address.
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

/// Message to request setting up transit auto-unseal
#[derive(Message, Debug)]
#[rtype(result = "Result<bool, vault::VaultError>")]
pub struct SetupTransitAutoUnseal {
    pub token: String,
    pub key_name: String,
}

/// Message for generating a wrapped token for auto-unseal
#[derive(Message, Debug)]
#[rtype(result = "Result<String, vault::VaultError>")]
pub struct GenerateWrappedToken {
    pub token: String,
    pub policy_name: String,
    pub ttl: u32,
}

/// Message for unwrapping a token
#[derive(Message, Debug)]
#[rtype(result = "Result<String, vault::VaultError>")]
pub struct UnwrapToken {
    pub wrapped_token: String,
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
                vault::init::init_vault(&addr, msg.secret_shares, msg.secret_threshold, None, None)
                    .await?;
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

impl Handler<SetupTransitAutoUnseal> for VaultActor {
    type Result = ResponseFuture<Result<bool, vault::VaultError>>;

    fn handle(&mut self, msg: SetupTransitAutoUnseal, _: &mut Self::Context) -> Self::Result {
        let vault_url = self.vault_addr.clone();
        Box::pin(async move {
            vault::autounseal::setup_transit_autounseal(&vault_url, &msg.token, &msg.key_name).await
        })
    }
}

impl Handler<GenerateWrappedToken> for VaultActor {
    type Result = ResponseFuture<Result<String, vault::VaultError>>;

    fn handle(&mut self, msg: GenerateWrappedToken, _: &mut Self::Context) -> Self::Result {
        let vault_url = self.vault_addr.clone();
        Box::pin(async move {
            vault::autounseal::generate_wrapped_transit_unseal_token(
                &vault_url,
                &msg.token,
                &msg.policy_name,
                msg.ttl,
            )
            .await
        })
    }
}

impl Handler<UnwrapToken> for VaultActor {
    type Result = ResponseFuture<Result<String, vault::VaultError>>;

    fn handle(&mut self, msg: UnwrapToken, _: &mut Self::Context) -> Self::Result {
        let vault_url = self.vault_addr.clone();
        Box::pin(
            async move { vault::autounseal::unwrap_token(&vault_url, &msg.wrapped_token).await },
        )
    }
}

#[async_trait]
impl VaultOperations for VaultActor {
    async fn init_vault(
        &self,
        secret_shares: u8,
        secret_threshold: u8,
    ) -> Result<crate::vault::InitResult, crate::vault::VaultError> {
        vault::init::init_vault(
            &self.vault_addr,
            secret_shares,
            secret_threshold,
            None,
            None,
        )
        .await
    }

    async fn unseal_vault(&self, keys: &[String]) -> Result<(), crate::vault::VaultError> {
        vault::init::unseal_vault(&self.vault_addr, keys).await
    }

    async fn setup_pki(
        &self,
        token: &str,
        domain: &str,
        ttl: &str,
        use_intermediate: bool,
        int_addr: Option<&str>,
        int_token: Option<&str>,
    ) -> Result<(String, String), crate::vault::VaultError> {
        vault::pki::setup_pki(
            &self.vault_addr,
            token,
            domain,
            ttl,
            use_intermediate,
            int_addr,
            int_token,
        )
        .await
    }

    async fn setup_approle(
        &self,
        token: &str,
        role_name: &str,
        policies: &[String],
    ) -> Result<vault::AppRoleCredentials, crate::vault::VaultError> {
        vault::auth::setup_approle(&self.vault_addr, token, role_name, policies).await
    }

    async fn setup_kubernetes_auth(
        &self,
        token: &str,
        role_name: &str,
        service_account: &str,
        namespace: &str,
        kubernetes_host: &str,
        kubernetes_ca_cert: &str,
    ) -> Result<(), crate::vault::VaultError> {
        vault::auth::setup_kubernetes_auth(
            &self.vault_addr,
            token,
            role_name,
            service_account,
            namespace,
            kubernetes_host,
            kubernetes_ca_cert,
        )
        .await
    }

    async fn issue_certificate(
        &self,
        token: &str,
        _domain: &str, // Prefix with underscore since it's unused
        common_name: &str,
        ttl: &str,
    ) -> Result<String, crate::vault::VaultError> {
        // Use the existing setup_pki function to create a certificate or find/create the proper issue_certificate function
        let cert =
            vault::pki::setup_pki(&self.vault_addr, token, common_name, ttl, false, None, None)
                .await?
                .0;
        Ok(cert)
    }

    async fn setup_transit_engine(&self, token: &str) -> Result<(), crate::vault::VaultError> {
        // Convert the bool result to () by ignoring the bool value
        vault::transit::setup_transit_engine(&self.vault_addr, token)
            .await
            .map(|_| ())
    }

    async fn create_transit_key(
        &self,
        token: &str,
        key_name: &str,
    ) -> Result<(), crate::vault::VaultError> {
        vault::transit::create_transit_key(&self.vault_addr, token, key_name).await
    }

    async fn create_transit_unseal_policy(
        &self,
        token: &str,
        policy_name: &str,
        key_name: &str,
    ) -> Result<(), crate::vault::VaultError> {
        vault::transit::create_transit_unseal_policy(&self.vault_addr, token, policy_name, key_name)
            .await
    }

    async fn generate_transit_unseal_token(
        &self,
        token: &str,
        policy_name: &str,
    ) -> Result<String, crate::vault::VaultError> {
        vault::transit::generate_transit_unseal_token(&self.vault_addr, token, policy_name).await
    }

    async fn generate_wrapped_transit_unseal_token(
        &self,
        token: &str,
        policy_name: &str,
        ttl: u32,
    ) -> Result<String, vault::VaultError> {
        vault::autounseal::generate_wrapped_transit_unseal_token(
            &self.vault_addr,
            token,
            policy_name,
            ttl,
        )
        .await
    }

    async fn unwrap_token(&self, wrapped_token: &str) -> Result<String, vault::VaultError> {
        vault::autounseal::unwrap_token(&self.vault_addr, wrapped_token).await
    }
}
