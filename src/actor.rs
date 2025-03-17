use actix::prelude::*;
use async_trait::async_trait;
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::broadcast;
use tokio::time;

use crate::interface::VaultInterface;
use crate::vault::common::VaultStatus;
use crate::vault::init::{InitResult, UnsealResult};
use crate::vault::setup_root::{setup_root_vault, RootSetupConfig};
use crate::vault::setup_sub::{setup_sub_vault, SubSetupConfig, SubSetupResult};
use crate::vault::{AutoUnsealResult, PkiResult, VaultError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealth {
    pub addr: String,
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub last_check: SystemTime,
}

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
    // Note: This used to be for single-step multi-tier. Remove or rename.
    SetupComplete {
        root_token: String,
        root_role: String,
        sub_token: String,
        int_role: String,
    },
    Error(String),
    VaultHealthUpdated {
        addr: String,
        health: VaultHealth,
    },
    VaultsListed {
        vaults: Vec<VaultHealth>,
    },
    TransitTokenUnwrapped {
        root_addr: String,
        unwrapped_token: String,
    },
}

#[derive(Clone)]
pub struct VaultActor {
    pub vault_addr: String,
    pub root_token: Option<String>,
    pub event_sender: Option<broadcast::Sender<VaultEvent>>,
    pub known_vaults: HashMap<String, VaultHealth>,
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
            known_vaults: HashMap::new(),
        }
    }

    /// Creates a VaultActor with a test configuration
    pub fn new_with_test_config<S: Into<String>>(
        vault_addr: S,
        event_sender: Option<broadcast::Sender<VaultEvent>>,
    ) -> Self {
        Self {
            vault_addr: vault_addr.into(),
            root_token: None,
            event_sender,
            known_vaults: HashMap::new(),
        }
    }

    pub async fn start_monitoring(&mut self) {
        let mut interval = time::interval(Duration::from_secs(30));

        // Register the primary vault
        self.register_vault(self.vault_addr.clone()).await;

        // Start the monitoring loop
        loop {
            interval.tick().await;

            // In each cycle, check all known vaults
            let addrs: Vec<String> = self.known_vaults.keys().cloned().collect();
            for addr in addrs {
                self.register_vault(addr).await;
            }
        }
    }

    async fn register_vault(&mut self, addr: String) {
        if !self.known_vaults.contains_key(&addr) {
            if let Ok(status) = self.check_status(&addr).await {
                let health = VaultHealth {
                    addr: addr.clone(),
                    initialized: status.initialized,
                    sealed: status.sealed,
                    standby: status.standby,
                    last_check: SystemTime::now(),
                };

                // Update in-memory cache
                self.known_vaults.insert(addr.clone(), health.clone());

                // Emit event
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(VaultEvent::VaultHealthUpdated {
                        addr: addr.clone(),
                        health,
                    });
                }
            }
        }
    }
}

impl Actor for VaultActor {
    type Context = Context<Self>;
}

/// Optional trait that you can use if you want to unify common Vault tasks
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

    // Removed the old single-step `setup_multi_tier` to avoid the "could not find setup" error
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
                Err(VaultError::Api(format!("Initialization error: {}", err)))
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

        // For demonstration: a simple root PKI (no intermediate)
        let common_name = role_name.clone();
        let ttl = "8760h";
        let intermediate = false;
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
        _recovery_shares: Option<u8>,
    ) -> Result<AutoUnsealResult, VaultError> {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();

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

                // Save the new root token
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
}

// -----------------------------------------------------------------------------
// Actor messages & handlers
// -----------------------------------------------------------------------------

/// Message for initializing a Vault with shares & threshold
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<InitResult, VaultError>")]
pub struct InitVault {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

impl Handler<InitVault> for VaultActor {
    type Result = ResponseFuture<Result<InitResult, VaultError>>;

    fn handle(&mut self, msg: InitVault, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move {
            actor
                .initialize(msg.secret_shares, msg.secret_threshold)
                .await
        }
        .boxed_local()
    }
}

/// Message for unsealing
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<UnsealResult, VaultError>")]
pub struct UnsealVault {
    pub keys: Vec<String>,
}

impl Handler<UnsealVault> for VaultActor {
    type Result = ResponseFuture<Result<UnsealResult, VaultError>>;

    fn handle(&mut self, msg: UnsealVault, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();
        async move { actor.unseal(&addr, msg.keys).await }.boxed_local()
    }
}

/// Message for checking status
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

/// Message for simple PKI
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

/// Message for auto-unseal
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<AutoUnsealResult, VaultError>")]
pub struct AutoUnseal;

impl Handler<AutoUnseal> for VaultActor {
    type Result = ResponseFuture<Result<AutoUnsealResult, VaultError>>;

    fn handle(&mut self, _msg: AutoUnseal, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move { actor.auto_unseal(None).await }.boxed_local()
    }
}

// Add new messages for setup operations
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, VaultError>")]
pub struct SetupRoot {
    pub addr: String,
    pub secret_shares: u8,
    pub secret_threshold: u8,
    pub key_name: String,
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, VaultError>")]
pub struct SetupSub {
    pub root_addr: String,
    pub root_token: String,
    pub sub_addr: String,
    pub domain: String,
    pub ttl: String,
}

impl Handler<SetupRoot> for VaultActor {
    type Result = ResponseFuture<Result<String, VaultError>>;

    fn handle(&mut self, msg: SetupRoot, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move {
            // Register the root vault
            actor.register_vault(msg.addr.clone()).await;

            let config = RootSetupConfig {
                root_addr: msg.addr.clone(),
                secret_shares: msg.secret_shares,
                secret_threshold: msg.secret_threshold,
                key_name: msg.key_name.clone(),
                mode: "local".to_string(),
                output_file: None,
            };

            match setup_root_vault(config).await {
                Ok(result) => {
                    // Trigger event, if sender exists
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::Initialized {
                            root_token: result.root_init.root_token.clone(),
                            keys: result.root_init.keys.clone(),
                        });
                    }

                    // Here, we return the unwrapped token for auto-unseal
                    Ok(result.unwrapped_token)
                }
                Err(e) => Err(VaultError::Api(format!("Root setup error: {}", e))),
            }
        }
        .boxed_local()
    }
}

impl Handler<SetupSub> for VaultActor {
    type Result = ResponseFuture<Result<String, VaultError>>;

    fn handle(&mut self, msg: SetupSub, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move {
            // Register both root and sub vaults
            actor.register_vault(msg.root_addr.clone()).await;
            actor.register_vault(msg.sub_addr.clone()).await;

            let config = SubSetupConfig {
                sub_addr: msg.sub_addr,
                domain: msg.domain,
                ttl: msg.ttl,
                root_addr: msg.root_addr,
                root_token: msg.root_token,
            };

            match setup_sub_vault(config).await {
                Ok(SubSetupResult {
                    sub_init,
                    pki_roles,
                }) => {
                    let int_role = pki_roles.1.clone();
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::SetupComplete {
                            root_token: sub_init.root_token.clone(),
                            root_role: pki_roles.0.clone(),
                            sub_token: sub_init.root_token,
                            int_role: pki_roles.1.clone(),
                        });
                    }
                    Ok(int_role)
                }
                Err(e) => Err(VaultError::Api(format!("Sub setup error: {}", e))),
            }
        }
        .boxed_local()
    }
}

// Add new message type for getting an unwrapped transit token
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, VaultError>")]
pub struct GetUnwrappedTransitToken {
    pub root_addr: String,
    pub root_token: String,
    pub key_name: String,
}

impl Handler<GetUnwrappedTransitToken> for VaultActor {
    type Result = ResponseFuture<Result<String, VaultError>>;

    fn handle(&mut self, msg: GetUnwrappedTransitToken, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        async move {
            log::debug!(
                "Getting unwrapped transit token from root vault at {}",
                msg.root_addr
            );

            // First, ensure transit auto-unseal is set up
            if let Err(e) = crate::vault::autounseal::setup_transit_autounseal(
                &msg.root_addr,
                &msg.root_token,
                &msg.key_name,
            )
            .await
            {
                return Err(VaultError::Api(format!(
                    "Failed to setup transit auto-unseal: {}",
                    e
                )));
            }

            // Generate a wrapped transit token
            let wrap_ttl = "300s";
            let wrapped_token = match crate::vault::transit::generate_wrapped_transit_token(
                &msg.root_addr,
                &msg.root_token,
                "autounseal", // policy name used in setup_transit_autounseal
                wrap_ttl,
            )
            .await
            {
                Ok(token) => token,
                Err(e) => {
                    return Err(VaultError::Api(format!(
                        "Failed to generate wrapped token: {}",
                        e
                    )))
                }
            };

            // Unwrap the token
            let unwrapped_token = match crate::vault::autounseal::unwrap_token(
                &msg.root_addr,
                &wrapped_token,
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return Err(VaultError::Api(format!("Failed to unwrap token: {}", e))),
            };

            log::debug!("Successfully obtained unwrapped transit token");

            // Emit event if sender is available
            if let Some(sender) = &actor.event_sender {
                let _ = sender.send(VaultEvent::TransitTokenUnwrapped {
                    root_addr: msg.root_addr,
                    unwrapped_token: unwrapped_token.clone(),
                });
            }

            Ok(unwrapped_token)
        }
        .boxed_local()
    }
}

// -----------------------------------------------------------------------------
// Start the actor with a broadcast channel
// -----------------------------------------------------------------------------

pub fn start_vault_actor_with_channel(
    vault_addr: &str,
) -> (Addr<VaultActor>, broadcast::Receiver<VaultEvent>) {
    let (tx, rx) = broadcast::channel(16);
    let actor = VaultActor::new(vault_addr, Some(tx));

    // Clone the actor before starting it
    let monitoring_actor = actor.clone();
    let addr = actor.start();

    // Start the monitoring in the background
    tokio::spawn(async move {
        let mut monitoring_actor = monitoring_actor;
        monitoring_actor.start_monitoring().await;
    });

    (addr, rx)
}

#[async_trait]
impl VaultInterface for VaultActor {
    async fn check_status(&self, addr: &str) -> Result<VaultStatus, VaultError> {
        match crate::vault::common::check_vault_status(addr).await {
            Ok(status) => {
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(VaultEvent::StatusChecked {
                        initialized: status.initialized,
                        sealed: status.sealed,
                        standby: status.standby,
                    });
                }
                Ok(status)
            }
            Err(err) => Err(VaultError::Api(format!("Status check error: {}", err))),
        }
    }

    async fn unseal(&self, addr: &str, keys: Vec<String>) -> Result<UnsealResult, VaultError> {
        match crate::vault::init::unseal_root_vault(addr, keys).await {
            Ok(unseal_resp) => {
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(VaultEvent::Unsealed {
                        progress: unseal_resp.progress,
                        threshold: unseal_resp.threshold,
                        sealed: unseal_resp.sealed,
                    });
                }
                Ok(unseal_resp)
            }
            Err(err) => Err(VaultError::Api(format!("Unseal error: {}", err))),
        }
    }

    async fn setup_root(
        &self,
        addr: &str,
        secret_shares: u8,
        secret_threshold: u8,
        key_name: &str,
    ) -> Result<String, VaultError> {
        let config = RootSetupConfig {
            root_addr: addr.to_string(),
            secret_shares,
            secret_threshold,
            key_name: key_name.to_string(),
            mode: "local".to_string(),
            output_file: None,
        };

        match setup_root_vault(config).await {
            Ok(result) => {
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(VaultEvent::Initialized {
                        root_token: result.root_init.root_token.clone(),
                        keys: result.root_init.keys.clone(),
                    });
                }
                Ok(result.unwrapped_token)
            }
            Err(e) => Err(VaultError::Api(format!("Root setup error: {}", e))),
        }
    }

    async fn setup_sub(
        &self,
        root_addr: &str,
        root_token: &str,
        sub_addr: &str,
        domain: &str,
        ttl: &str,
    ) -> Result<String, VaultError> {
        let config = SubSetupConfig {
            sub_addr: sub_addr.to_string(),
            domain: domain.to_string(),
            ttl: ttl.to_string(),
            root_addr: root_addr.to_string(),
            root_token: root_token.to_string(),
        };

        match setup_sub_vault(config).await {
            Ok(SubSetupResult {
                sub_init,
                pki_roles,
            }) => {
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(VaultEvent::SetupComplete {
                        root_token: sub_init.root_token.clone(),
                        root_role: pki_roles.0.clone(),
                        sub_token: sub_init.root_token,
                        int_role: pki_roles.1.clone(),
                    });
                }
                Ok(pki_roles.1)
            }
            Err(e) => Err(VaultError::Api(format!("Sub setup error: {}", e))),
        }
    }

    async fn get_unwrapped_transit_token(
        &self,
        root_addr: &str,
        root_token: &str,
        key_name: &str,
    ) -> Result<String, VaultError> {
        log::debug!(
            "Getting unwrapped transit token from root vault at {}",
            root_addr
        );

        // First, ensure transit auto-unseal is set up
        if let Err(e) =
            crate::vault::autounseal::setup_transit_autounseal(root_addr, root_token, key_name)
                .await
        {
            return Err(VaultError::Api(format!(
                "Failed to setup transit auto-unseal: {}",
                e
            )));
        }

        // Generate a wrapped transit token
        let wrap_ttl = "300s";
        let wrapped_token = match crate::vault::transit::generate_wrapped_transit_token(
            root_addr,
            root_token,
            "autounseal", // policy name used in setup_transit_autounseal
            wrap_ttl,
        )
        .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(VaultError::Api(format!(
                    "Failed to generate wrapped token: {}",
                    e
                )))
            }
        };

        // Unwrap the token
        let unwrapped_token =
            match crate::vault::autounseal::unwrap_token(root_addr, &wrapped_token).await {
                Ok(token) => token,
                Err(e) => return Err(VaultError::Api(format!("Failed to unwrap token: {}", e))),
            };

        log::debug!("Successfully obtained unwrapped transit token");

        // Emit event if sender is available
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(VaultEvent::TransitTokenUnwrapped {
                root_addr: root_addr.to_string(),
                unwrapped_token: unwrapped_token.clone(),
            });
        }

        Ok(unwrapped_token)
    }
}
