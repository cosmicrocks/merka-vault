use actix::prelude::*;
use async_trait::async_trait;
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::vault::common::VaultStatus;
use crate::vault::setup::{SetupResult, VaultSetupConfig};
use crate::vault::{AutoUnsealResult, InitResult, PkiResult, UnsealResult, VaultError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultEvent {
    Initialized {
        root_token: String,
        keys: Vec<String>,
    },
    Unsealed {
        progress: u8,
        threshold: u8,
        sealed: bool,
    },
    PkiSetupComplete {
        role_name: String,
        cert_chain: String,
    },
    AutounsealComplete {
        root_token: String,
        recovery_keys: Option<Vec<String>>,
    },
    StatusChecked {
        initialized: bool,
        sealed: bool,
        standby: bool,
    },
    SetupComplete {
        root_token: String,
        root_role: String,
        sub_token: String,
        int_role: String,
    },
    Error(String),
}

// Implement Clone for VaultActor
#[derive(Clone)]
pub struct VaultActor {
    pub vault_addr: String,
    pub root_token: Option<String>,
    pub event_sender: Option<broadcast::Sender<VaultEvent>>,
}

impl VaultActor {
    pub fn new<S: Into<String>>(
        vault_addr: S,
        event_sender: Option<broadcast::Sender<VaultEvent>>,
    ) -> Self {
        Self {
            vault_addr: vault_addr.into(),
            root_token: None,
            event_sender,
        }
    }
}

impl Actor for VaultActor {
    type Context = Context<Self>;
}

/// Common operations that both CLI and Actor should support
#[async_trait]
pub trait VaultOperations {
    /// Initialize a new Vault instance
    async fn initialize(
        &mut self,
        secret_shares: u8,
        secret_threshold: u8,
    ) -> Result<InitResult, VaultError>;

    /// Unseal a vault with key shares
    async fn unseal(&mut self, keys: Vec<String>) -> Result<UnsealResult, VaultError>;

    /// Check Vault status
    async fn status(&self) -> Result<VaultStatus, VaultError>;

    /// Setup PKI infrastructure
    async fn setup_pki(&mut self, role_name: String) -> Result<PkiResult, VaultError>;

    /// Perform auto-unsealing
    async fn auto_unseal(
        &mut self,
        recovery_shares: Option<u8>,
    ) -> Result<AutoUnsealResult, VaultError>;

    /// Setup multi-tier vault with autounseal and PKI
    async fn setup_multi_tier(
        &mut self,
        config: VaultSetupConfig,
    ) -> Result<SetupResult, VaultError>;
}

#[async_trait]
impl VaultOperations for VaultActor {
    async fn initialize(
        &mut self,
        secret_shares: u8,
        secret_threshold: u8,
    ) -> Result<InitResult, VaultError> {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();

        match crate::vault::init::init_vault(&addr, secret_shares, secret_threshold, None, None)
            .await
        {
            Ok(init_resp) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Initialized {
                        root_token: init_resp.root_token.clone(),
                        keys: init_resp.keys.clone(),
                    });
                }
                self.root_token = Some(init_resp.root_token.clone());
                Ok(init_resp)
            }
            Err(err) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                }
                Err(VaultError::Api(format!("Auto-unseal error: {}", err)))
            }
        }
    }

    async fn unseal(&mut self, keys: Vec<String>) -> Result<UnsealResult, VaultError> {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();

        match crate::vault::init::unseal_root_vault(&addr, keys).await {
            Ok(unseal_resp) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Unsealed {
                        progress: unseal_resp.progress,
                        threshold: unseal_resp.threshold,
                        sealed: unseal_resp.sealed,
                    });
                }
                Ok(unseal_resp)
            }
            Err(err) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                }
                Err(VaultError::Api(format!("Unseal error: {}", err)))
            }
        }
    }

    async fn status(&self) -> Result<VaultStatus, VaultError> {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();

        match crate::vault::common::check_vault_status(&addr).await {
            Ok(status) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::StatusChecked {
                        initialized: status.initialized,
                        sealed: status.sealed,
                        standby: status.standby,
                    });
                }
                Ok(status)
            }
            Err(err) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                }
                Err(VaultError::Api(format!("Status check error: {}", err)))
            }
        }
    }

    async fn setup_pki(&mut self, role_name: String) -> Result<PkiResult, VaultError> {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();
        let token = self.root_token.clone().unwrap_or_default();

        // Default values for other required parameters
        let common_name = role_name.clone(); // Using role name as common name
        let ttl = "8760h"; // Default TTL (1 year)
        let intermediate = false; // Simple setup, no intermediate
        let intermediate_addr = None;
        let int_token = None;

        match crate::vault::pki::setup_pki(
            &addr,
            &token,
            &common_name,
            ttl,
            intermediate,
            intermediate_addr,
            int_token,
        )
        .await
        {
            Ok((cert_chain, role)) => {
                let result = PkiResult {
                    cert_chain,
                    role_name: role,
                };

                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::PkiSetupComplete {
                        role_name: result.role_name.clone(),
                        cert_chain: result.cert_chain.clone(),
                    });
                }
                Ok(result)
            }
            Err(err) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                }
                Err(VaultError::Api(format!("PKI setup error: {}", err)))
            }
        }
    }

    async fn auto_unseal(
        &mut self,
        _recovery_shares: Option<u8>, // Prefix with underscore to mark as intentionally unused
    ) -> Result<AutoUnsealResult, VaultError> {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();

        // Using the autounseal module instead of setup module
        match crate::vault::autounseal::init_with_autounseal(&addr).await {
            Ok(init_result) => {
                let auto_result = AutoUnsealResult {
                    root_token: init_result.root_token.clone(),
                    recovery_keys: init_result.recovery_keys.clone(),
                    success: true,
                };

                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::AutounsealComplete {
                        root_token: auto_result.root_token.clone(),
                        recovery_keys: auto_result.recovery_keys.clone(),
                    });
                }

                // Store the root token
                self.root_token = Some(init_result.root_token);

                Ok(auto_result)
            }
            Err(err) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                }
                Err(VaultError::Api(format!("Auto-unseal error: {}", err)))
            }
        }
    }

    async fn setup_multi_tier(
        &mut self,
        config: VaultSetupConfig,
    ) -> Result<SetupResult, VaultError> {
        let event_sender = self.event_sender.clone();

        match crate::vault::setup::setup_multi_tier_vault(config).await {
            Ok(result) => {
                // Create a SetupResult from the VaultSetupResult
                let setup_result = SetupResult {
                    root_init: result.root_init,
                    root_role: String::new(), // Fill with appropriate values
                    sub_init: crate::vault::AutoUnsealResult {
                        root_token: String::new(), // Fill with appropriate values
                        recovery_keys: None,
                        success: true,
                    },
                    int_role: String::new(), // Fill with appropriate values
                };

                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::SetupComplete {
                        root_token: setup_result.root_init.root_token.clone(),
                        root_role: setup_result.root_role.clone(),
                        sub_token: setup_result.sub_init.root_token.clone(),
                        int_role: setup_result.int_role.clone(),
                    });
                }

                // Update the root token
                self.root_token = Some(setup_result.root_init.root_token.clone());

                Ok(setup_result)
            }
            Err(err) => {
                if let Some(sender) = &event_sender {
                    let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                }
                Err(VaultError::Api(format!("Setup error: {}", err)))
            }
        }
    }
}

/// Mark the message type with Clone.
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<InitResult, VaultError>")]
pub struct InitVault {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

impl Handler<InitVault> for VaultActor {
    type Result = ResponseFuture<Result<InitResult, VaultError>>;

    fn handle(&mut self, msg: InitVault, _ctx: &mut Context<Self>) -> Self::Result {
        // Clone self since we need to move it into the async block
        let mut actor = self.clone();

        async move {
            actor
                .initialize(msg.secret_shares, msg.secret_threshold)
                .await
        }
        .boxed_local()
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<UnsealResult, VaultError>")]
pub struct UnsealVault {
    pub keys: Vec<String>,
}

impl Handler<UnsealVault> for VaultActor {
    type Result = ResponseFuture<Result<UnsealResult, VaultError>>;

    fn handle(&mut self, msg: UnsealVault, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();

        async move { actor.unseal(msg.keys).await }.boxed_local()
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<VaultStatus, VaultError>")]
pub struct CheckStatus;

impl Handler<CheckStatus> for VaultActor {
    type Result = ResponseFuture<Result<VaultStatus, VaultError>>;

    fn handle(&mut self, _msg: CheckStatus, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();

        async move { actor.status().await }.boxed_local()
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<PkiResult, VaultError>")]
pub struct SetupPki {
    pub role_name: String,
}

impl Handler<SetupPki> for VaultActor {
    type Result = ResponseFuture<Result<PkiResult, VaultError>>;

    fn handle(&mut self, msg: SetupPki, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();

        async move { actor.setup_pki(msg.role_name).await }.boxed_local()
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<SetupResult, VaultError>")]
pub struct SetupMultiTier {
    pub config: VaultSetupConfig,
}

impl Handler<SetupMultiTier> for VaultActor {
    type Result = ResponseFuture<Result<SetupResult, VaultError>>;

    fn handle(&mut self, msg: SetupMultiTier, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();

        async move { actor.setup_multi_tier(msg.config).await }.boxed_local()
    }
}

/// Public helper function to start the actor with a broadcast channel.
pub fn start_vault_actor_with_channel(
    vault_addr: &str,
) -> (Addr<VaultActor>, broadcast::Receiver<VaultEvent>) {
    let (tx, rx) = broadcast::channel(16);
    let actor = VaultActor::new(vault_addr, Some(tx));
    let addr = actor.start();
    (addr, rx)
}
