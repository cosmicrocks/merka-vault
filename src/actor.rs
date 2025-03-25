use actix::prelude::*;
use async_trait::async_trait;
use futures_util::FutureExt;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::broadcast;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::interface::VaultInterface;
use crate::vault::common::VaultStatus;
use crate::vault::init::{InitResult, UnsealResult};
use crate::vault::setup_root::{setup_root_vault, RootSetupConfig};
use crate::vault::setup_sub::{setup_sub_vault, SubSetupConfig, SubSetupResult};
use crate::vault::{AutoUnsealResult, PkiResult, VaultError};

/// Error type for the actor module
#[derive(Debug, thiserror::Error)]
pub enum ActorError {
    #[error("Vault API error: {0}")]
    VaultApi(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Actor operation failed: {0}")]
    Operation(String),

    #[error("Actor message handling failed: {0}")]
    Messaging(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("HTTP error: {0}")]
    HttpError(String),
}

/// Add conversion from VaultError to ActorError
impl From<VaultError> for ActorError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::Api(msg) => ActorError::VaultApi(msg),
            VaultError::ApiError(msg) => ActorError::VaultApi(msg),
            VaultError::Network(msg) => ActorError::Network(msg),
            VaultError::Connection(msg) => ActorError::Network(msg),
            VaultError::ParseError(msg) => ActorError::VaultApi(format!("Parse error: {}", msg)),
            VaultError::Parsing(msg) => ActorError::VaultApi(format!("Parsing error: {}", msg)),
            VaultError::HttpStatus(code, msg) => {
                ActorError::VaultApi(format!("HTTP {}: {}", code, msg))
            }
            VaultError::AlreadyInitialized => {
                ActorError::VaultApi("Vault is already initialized".to_string())
            }
            VaultError::Sealed(msg) => ActorError::VaultApi(format!("Vault is sealed: {}", msg)),
            VaultError::RequestError(msg) => ActorError::Network(format!("Request error: {}", msg)),
            VaultError::Reqwest(err) => ActorError::Network(format!("Reqwest error: {}", err)),
            VaultError::Json(err) => ActorError::VaultApi(format!("JSON error: {}", err)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealth {
    pub addr: String,
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub last_check: SystemTime,
    pub is_auto_unsealed: bool,
    pub unsealer_addr: Option<String>,
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
    TokenVerified {
        valid: bool,
        message: String,
    },
    TransitSetup {
        success: bool,
        key_name: String,
    },
    AutoUnsealDependencyError {
        sub_addr: String,
        root_addr: String,
        error: String,
    },
}

#[derive(Clone)]
pub struct VaultActor {
    pub vault_addr: String,
    pub root_token: Option<String>,
    pub event_sender: Option<broadcast::Sender<VaultEvent>>,
    pub known_vaults: HashMap<String, VaultHealth>,
    pub unsealer_relationships: HashMap<String, String>,
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
            unsealer_relationships: HashMap::new(),
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
            unsealer_relationships: HashMap::new(),
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

            // After checking the vaults, verify their relationships
            self.check_auto_unseal_dependencies().await;
        }
    }

    // Method to check auto-unseal dependencies
    async fn check_auto_unseal_dependencies(&mut self) {
        // Add debug logging for the current state
        debug!("Checking auto-unseal dependencies. Current state:");
        debug!(
            "Known vaults: {:?}",
            self.known_vaults.keys().collect::<Vec<_>>()
        );
        debug!("Unsealer relationships: {:?}", self.unsealer_relationships);

        // For each relationship, check if root vault is sealed or not initialized
        for (sub_addr, root_addr) in self.unsealer_relationships.clone() {
            // First refresh the vault statuses
            if let Ok(root_status) = self.check_status(&root_addr).await {
                if let Ok(sub_status) = self.check_status(&sub_addr).await {
                    // Update the known_vaults map with fresh statuses
                    let mut root_health = self
                        .known_vaults
                        .get(&root_addr)
                        .cloned()
                        .unwrap_or_else(|| VaultHealth {
                            addr: root_addr.clone(),
                            initialized: root_status.initialized,
                            sealed: root_status.sealed,
                            standby: root_status.standby,
                            last_check: SystemTime::now(),
                            is_auto_unsealed: false,
                            unsealer_addr: None,
                        });

                    // Update with fresh status
                    root_health.initialized = root_status.initialized;
                    root_health.sealed = root_status.sealed;
                    root_health.standby = root_status.standby;
                    root_health.last_check = SystemTime::now();

                    // Same for sub vault
                    let mut sub_health =
                        self.known_vaults
                            .get(&sub_addr)
                            .cloned()
                            .unwrap_or_else(|| VaultHealth {
                                addr: sub_addr.clone(),
                                initialized: sub_status.initialized,
                                sealed: sub_status.sealed,
                                standby: sub_status.standby,
                                last_check: SystemTime::now(),
                                is_auto_unsealed: true,
                                unsealer_addr: Some(root_addr.clone()),
                            });

                    // Update with fresh status
                    sub_health.initialized = sub_status.initialized;
                    sub_health.sealed = sub_status.sealed;
                    sub_health.standby = sub_status.standby;
                    sub_health.last_check = SystemTime::now();

                    // Update the maps
                    self.known_vaults
                        .insert(root_addr.clone(), root_health.clone());
                    self.known_vaults
                        .insert(sub_addr.clone(), sub_health.clone());

                    // Log statuses for debugging
                    debug!(
                        "Checking auto-unseal dependency: root={} (sealed={}, init={}), sub={} (sealed={}, init={})",
                        root_addr, root_health.sealed, root_health.initialized,
                        sub_addr, sub_health.sealed, sub_health.initialized
                    );

                    // The critical condition is if the root vault is sealed or not initialized
                    if root_health.sealed || !root_health.initialized {
                        let error_msg = if root_health.sealed {
                            format!(
                                "Sub vault at {} cannot auto-unseal because root vault at {} is sealed",
                                sub_addr, root_addr
                            )
                        } else if !root_health.initialized {
                            format!("Sub vault at {} cannot auto-unseal because root vault at {} is not initialized", sub_addr, root_addr)
                        } else {
                            format!(
                                "Sub vault at {} cannot auto-unseal due to issues with root vault at {}",
                                sub_addr, root_addr
                            )
                        };

                        debug!("Auto-unseal dependency error detected: {}", error_msg);

                        // Emit an event for this error condition
                        if let Some(sender) = &self.event_sender {
                            debug!(
                                "Sending AutoUnsealDependencyError event for sub={}, root={}",
                                sub_addr, root_addr
                            );
                            let send_result = sender.send(VaultEvent::AutoUnsealDependencyError {
                                sub_addr: sub_addr.clone(),
                                root_addr: root_addr.clone(),
                                error: error_msg.clone(),
                            });

                            if let Err(e) = &send_result {
                                debug!("Failed to send AutoUnsealDependencyError event: {}", e);
                            } else {
                                debug!("Successfully sent AutoUnsealDependencyError event");
                            }

                            // Also send a general error for backwards compatibility
                            let general_result = sender.send(VaultEvent::Error(error_msg));
                            if let Err(e) = &general_result {
                                debug!("Failed to send Error event: {}", e);
                            }
                        } else {
                            warn!(
                                "No event sender available to send AutoUnsealDependencyError event"
                            );
                        }
                    } else {
                        debug!(
                            "No dependency issues detected between root={} and sub={}",
                            root_addr, sub_addr
                        );
                    }
                } else {
                    warn!("Failed to check status for sub vault at {}", sub_addr);
                }
            } else {
                warn!("Failed to check status for root vault at {}", root_addr);
            }
        }
    }

    async fn register_vault(&mut self, addr: String) {
        let should_check_config = !self.known_vaults.contains_key(&addr);

        if let Ok(status) = self.check_status(&addr).await {
            // Detect if this is an auto-unsealed vault by checking its configuration
            let is_auto_unsealed = should_check_config && self.check_is_auto_unsealed(&addr).await;
            let unsealer_addr = if is_auto_unsealed {
                let root_addr = self.get_unsealer_address(&addr).await;
                if let Some(root) = &root_addr {
                    // Register the relationship for dependency checking
                    self.unsealer_relationships
                        .insert(addr.clone(), root.clone());
                }
                root_addr
            } else {
                None
            };

            let health = VaultHealth {
                addr: addr.clone(),
                initialized: status.initialized,
                sealed: status.sealed,
                standby: status.standby,
                last_check: SystemTime::now(),
                is_auto_unsealed,
                unsealer_addr,
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

    // New helper method to check if a vault is using auto-unseal
    async fn check_is_auto_unsealed(&self, addr: &str) -> bool {
        // Try to retrieve the seal configuration to determine if transit seal is being used
        let client = reqwest::Client::new();
        let url = format!("{}/v1/sys/seal-status", addr);

        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                // Parse the response to check seal type
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(seal_type) = json.get("type") {
                        // If seal type is "transit", this is an auto-unsealed vault
                        return seal_type.as_str().unwrap_or("").contains("transit");
                    }
                }
            }
        }

        false
    }

    // New helper method to get the unsealer address for a sub vault
    async fn get_unsealer_address(&self, addr: &str) -> Option<String> {
        // Try to get the configuration which should include the transit seal details
        let client = reqwest::Client::new();
        let url = format!("{}/v1/sys/config/state/sanitized", addr);

        // Note: This endpoint requires high privileges and may not be accessible
        // For real implementations, we might need to store this relationship when setting up
        // In this example, we'll fall back to checking the config if accessible,
        // or infer from seal type and relationships we observe

        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(seal) = json.get("seal") {
                        if let Some(config) = seal.get("config") {
                            if let Some(address) = config.get("address") {
                                return address.as_str().map(|s| s.to_string());
                            }
                        }
                    }
                }
            }
        }

        // If we couldn't get the config, check if we've already tracked this relationship elsewhere
        // In a real implementation, this would be stored when setting up the auto-unseal relationship
        None
    }

    // Add a method to manually trigger the dependency check
    pub async fn check_dependencies_now(&mut self) {
        // First update status of all known vaults
        let addrs: Vec<String> = self.known_vaults.keys().cloned().collect();
        for addr in addrs {
            self.register_vault(addr).await;
        }

        // Then run the dependency check
        self.check_auto_unseal_dependencies().await;
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
#[rtype(result = "Result<InitResult, ActorError>")]
pub struct InitVault {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

impl Handler<InitVault> for VaultActor {
    type Result = ResponseFuture<Result<InitResult, ActorError>>;

    fn handle(&mut self, msg: InitVault, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move {
            actor
                .initialize(msg.secret_shares, msg.secret_threshold)
                .await
                .map_err(ActorError::from)
        }
        .boxed_local()
    }
}

/// Message for unsealing a Vault
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<UnsealResult, ActorError>")]
pub struct UnsealVault {
    pub keys: Vec<String>,
}

impl Handler<UnsealVault> for VaultActor {
    type Result = ResponseFuture<Result<UnsealResult, ActorError>>;

    fn handle(&mut self, msg: UnsealVault, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();
        async move {
            actor
                .unseal(&addr, msg.keys)
                .await
                .map_err(ActorError::from)
        }
        .boxed_local()
    }
}

/// Message for checking status
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<VaultStatus, ActorError>")]
pub struct CheckStatus;

impl Handler<CheckStatus> for VaultActor {
    type Result = ResponseFuture<Result<VaultStatus, ActorError>>;

    fn handle(&mut self, _: CheckStatus, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();
        async move { actor.check_status(&addr).await.map_err(ActorError::from) }.boxed_local()
    }
}

/// Message for simple PKI
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<PkiResult, ActorError>")]
pub struct SetupPki {
    pub role_name: String,
}

impl Handler<SetupPki> for VaultActor {
    type Result = ResponseFuture<Result<PkiResult, ActorError>>;

    fn handle(&mut self, msg: SetupPki, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move {
            actor
                .setup_pki(msg.role_name)
                .await
                .map_err(ActorError::from)
        }
        .boxed_local()
    }
}

/// Message for auto-unseal
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<AutoUnsealResult, ActorError>")]
pub struct AutoUnseal;

impl Handler<AutoUnseal> for VaultActor {
    type Result = ResponseFuture<Result<AutoUnsealResult, ActorError>>;

    fn handle(&mut self, _msg: AutoUnseal, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move { actor.auto_unseal(None).await.map_err(ActorError::from) }.boxed_local()
    }
}

// Add new messages for setup operations
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct SetupRoot {
    pub addr: String,
    pub secret_shares: u8,
    pub secret_threshold: u8,
    pub key_name: String,
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct SetupSub {
    pub root_addr: String,
    pub root_token: String,
    pub sub_addr: String,
    pub domain: String,
    pub ttl: String,
}

impl Handler<SetupRoot> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

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
                Err(e) => Err(ActorError::VaultApi(format!("Root setup error: {}", e))),
            }
        }
        .boxed_local()
    }
}

impl Handler<SetupSub> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

    fn handle(&mut self, msg: SetupSub, _ctx: &mut Context<Self>) -> Self::Result {
        let mut actor = self.clone();
        async move {
            // Register both root and sub vaults
            actor.register_vault(msg.root_addr.clone()).await;
            actor.register_vault(msg.sub_addr.clone()).await;

            // Register the auto-unseal relationship for monitoring
            actor
                .unsealer_relationships
                .insert(msg.sub_addr.clone(), msg.root_addr.clone());

            let config = SubSetupConfig {
                sub_addr: msg.sub_addr.clone(),
                domain: msg.domain,
                ttl: msg.ttl,
                root_addr: msg.root_addr.clone(),
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
                Err(e) => Err(ActorError::VaultApi(format!("Sub setup error: {}", e))),
            }
        }
        .boxed_local()
    }
}

// Add new message type for getting an unwrapped transit token
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct GetUnwrappedTransitToken {
    pub root_addr: String,
    pub root_token: String,
    pub key_name: String,
}

impl Handler<GetUnwrappedTransitToken> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

    fn handle(&mut self, msg: GetUnwrappedTransitToken, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        async move {
            debug!(
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
                return Err(ActorError::VaultApi(format!(
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
                    return Err(ActorError::VaultApi(format!(
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
                Err(e) => {
                    return Err(ActorError::VaultApi(format!(
                        "Failed to unwrap token: {}",
                        e
                    )))
                }
            };

            debug!("Successfully obtained unwrapped transit token");

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

// Add these new message types after the existing actor message definitions

/// Message for setting up transit auto-unseal
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct SetupTransit {
    pub token: String,
    pub key_name: String,
}

impl Handler<SetupTransit> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

    fn handle(&mut self, msg: SetupTransit, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();

        async move {
            match crate::vault::autounseal::setup_transit_autounseal(
                &addr,
                &msg.token,
                &msg.key_name,
            )
            .await
            {
                Ok(_result) => {
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::TransitSetup {
                            success: true,
                            key_name: msg.key_name.clone(),
                        });
                    }
                    Ok(msg.key_name)
                }
                Err(e) => {
                    if let Some(sender) = &actor.event_sender {
                        let _ =
                            sender.send(VaultEvent::Error(format!("Transit setup error: {}", e)));
                    }
                    Err(ActorError::from(e))
                }
            }
        }
        .boxed_local()
    }
}

/// Message for generating a wrapped transit token
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct GenerateWrappedToken {
    pub policy_name: String,
    pub wrap_ttl: String,
    pub token: String,
}

impl Handler<GenerateWrappedToken> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

    fn handle(&mut self, msg: GenerateWrappedToken, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();

        async move {
            match crate::vault::transit::generate_wrapped_transit_token(
                &addr,
                &msg.token,
                &msg.policy_name,
                &msg.wrap_ttl,
            )
            .await
            {
                Ok(wrapped_token) => Ok(wrapped_token),
                Err(e) => {
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::Error(format!(
                            "Wrapped token generation error: {}",
                            e
                        )));
                    }
                    Err(ActorError::from(e))
                }
            }
        }
        .boxed_local()
    }
}

/// Message for unwrapping a token
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct UnwrapToken {
    pub wrapped_token: String,
}

impl Handler<UnwrapToken> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

    fn handle(&mut self, msg: UnwrapToken, _ctx: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();

        async move {
            match crate::vault::autounseal::unwrap_token(&addr, &msg.wrapped_token).await {
                Ok(unwrapped_token) => {
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::TransitTokenUnwrapped {
                            root_addr: addr.clone(),
                            unwrapped_token: unwrapped_token.clone(),
                        });
                    }
                    Ok(unwrapped_token)
                }
                Err(e) => {
                    if let Some(sender) = &actor.event_sender {
                        let _ =
                            sender.send(VaultEvent::Error(format!("Token unwrap error: {}", e)));
                    }
                    Err(ActorError::from(e))
                }
            }
        }
        .boxed_local()
    }
}

/// Message for verifying token permissions
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<bool, ActorError>")]
pub struct VerifyTokenPermissions {
    pub token: String,
    pub key_name: String,
}

impl Handler<VerifyTokenPermissions> for VaultActor {
    type Result = ResponseFuture<Result<bool, ActorError>>;

    fn handle(&mut self, msg: VerifyTokenPermissions, _: &mut Context<Self>) -> Self::Result {
        let actor = self.clone();
        let addr = actor.vault_addr.clone();

        Box::pin(async move {
            // Try a simple encryption operation to verify the token has the correct permissions
            let client = reqwest::Client::new();
            let encrypt_resp = client
                .post(format!("{}/v1/transit/encrypt/{}", addr, msg.key_name))
                .header("X-Vault-Token", &msg.token)
                .json(&serde_json::json!({
                    "plaintext": "dGVzdA==" // Base64 encoded "test"
                }))
                .send()
                .await;

            match encrypt_resp {
                Ok(resp) => {
                    if resp.status().is_success() {
                        // Successfully accessed a path that requires root permissions
                        if let Some(sender) = &actor.event_sender {
                            let _ = sender.send(VaultEvent::TokenVerified {
                                valid: true,
                                message: "Token has transit permissions".into(),
                            });
                        }
                        Ok(true)
                    } else {
                        let body = resp
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());
                        if let Some(sender) = &actor.event_sender {
                            let _ = sender.send(VaultEvent::TokenVerified {
                                valid: false,
                                message: format!("Token verification failed: {}", body),
                            });
                        }
                        Err(ActorError::VaultApi(format!(
                            "Token permission verification failed: {}",
                            body
                        )))
                    }
                }
                Err(e) => {
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::TokenVerified {
                            valid: false,
                            message: format!("Token verification failed: {}", e),
                        });
                    }
                    Err(ActorError::Network(format!(
                        "Token verification request failed: {}",
                        e
                    )))
                }
            }
        })
    }
}

// Add new message type for checking dependencies immediately
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<(), ActorError>")]
pub struct CheckDependencies;

/// Helper function to check the health status of a vault
async fn check_vault_health(
    client: &reqwest::Client,
    addr: &str,
) -> Result<VaultHealth, ActorError> {
    let status_url = format!("{}/v1/sys/health", addr);

    let response = client
        .get(&status_url)
        .send()
        .await
        .map_err(|e| ActorError::Network(format!("Failed to connect to {}: {}", addr, e)))?;

    if !response.status().is_success() {
        return if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
            // Sealed vault returns 500 status, but we still want the response body
            let health_data: serde_json::Value = response.json().await.map_err(|e| {
                ActorError::VaultApi(format!("Could not parse vault health response: {}", e))
            })?;

            // Extract fields from JSON
            let initialized = health_data
                .get("initialized")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let sealed = health_data
                .get("sealed")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let standby = health_data
                .get("standby")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            Ok(VaultHealth {
                addr: addr.to_string(),
                initialized,
                sealed,
                standby,
                last_check: std::time::SystemTime::now(),
                is_auto_unsealed: false, // Will be updated later if needed
                unsealer_addr: None,
            })
        } else {
            Err(ActorError::VaultApi(format!(
                "Vault health check failed with status code: {}",
                response.status()
            )))
        };
    }

    // Parse response
    let health_data: serde_json::Value = response.json().await.map_err(|e| {
        ActorError::VaultApi(format!("Could not parse vault health response: {}", e))
    })?;

    // Extract fields from JSON
    let initialized = health_data
        .get("initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sealed = health_data
        .get("sealed")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let standby = health_data
        .get("standby")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(VaultHealth {
        addr: addr.to_string(),
        initialized,
        sealed,
        standby,
        last_check: std::time::SystemTime::now(),
        is_auto_unsealed: false, // Will be updated later if needed
        unsealer_addr: None,
    })
}

/// Function to check auto-unseal dependencies between a sub vault and its root vault
async fn check_auto_unseal_dependencies(
    _client: &reqwest::Client,
    sub_addr: &str,
    sub_health: &VaultHealth,
    root_addr: &str,
    root_health: &VaultHealth,
    event_tx: &broadcast::Sender<VaultEvent>,
) -> Result<(), ActorError> {
    // Log health status for debugging
    info!(
        "Checking auto-unseal dependency: sub_vault={} (sealed={}, init={}), root_vault={} (sealed={}, init={})",
        sub_addr, sub_health.sealed, sub_health.initialized,
        root_addr, root_health.sealed, root_health.initialized
    );

    // Check for dependency issues
    if root_health.sealed || !root_health.initialized {
        // Root vault has issues that would prevent auto-unsealing
        let error_msg = if root_health.sealed {
            format!(
                "Root vault at {} is sealed, which prevents auto-unsealing of the sub vault at {}",
                root_addr, sub_addr
            )
        } else {
            format!("Root vault at {} is not initialized, which prevents auto-unsealing of the sub vault at {}",
                    root_addr, sub_addr)
        };

        error!("Auto-unseal dependency issue detected: {}", error_msg);

        // Emit event
        if let Err(e) = event_tx.send(VaultEvent::AutoUnsealDependencyError {
            sub_addr: sub_addr.to_string(),
            root_addr: root_addr.to_string(),
            error: error_msg,
        }) {
            error!("Failed to send AutoUnsealDependencyError event: {}", e);
        }
    }

    Ok(())
}

impl Handler<CheckDependencies> for VaultActor {
    type Result = ResponseFuture<Result<(), ActorError>>;

    fn handle(&mut self, _msg: CheckDependencies, _ctx: &mut Self::Context) -> Self::Result {
        let unsealer_relationships = self.unsealer_relationships.clone();
        let known_vaults = self.known_vaults.clone();
        let event_tx = self.event_sender.clone().unwrap();
        let client = reqwest::Client::new();

        Box::pin(async move {
            info!("Checking auto-unseal dependencies...");

            // Log current state for debugging
            info!("Known vaults: {:?}", known_vaults);
            info!("Unsealer relationships: {:?}", unsealer_relationships);

            // For each sub vault that has a root vault for auto-unsealing
            for (sub_addr, root_addr) in &unsealer_relationships {
                // Aggressively check root vault health first
                let root_health = match check_vault_health(&client, root_addr).await {
                    Ok(health) => {
                        info!(
                            "Root vault health at {}: sealed={}, initialized={}",
                            root_addr, health.sealed, health.initialized
                        );
                        health
                    }
                    Err(e) => {
                        // Root vault is unreachable - emit error event
                        error!("Root vault {} is unreachable: {}", root_addr, e);
                        let error_msg = format!("Root vault is unreachable: {}", e);

                        if let Err(e) = event_tx.send(VaultEvent::AutoUnsealDependencyError {
                            sub_addr: sub_addr.clone(),
                            root_addr: root_addr.clone(),
                            error: error_msg,
                        }) {
                            error!("Failed to send event: {}", e);
                        }

                        continue;
                    }
                };

                // Check if root vault is in a state that prevents auto-unseal
                if root_health.sealed || !root_health.initialized {
                    // Root vault is sealed or not initialized - emit error event
                    let error_msg = if root_health.sealed {
                        format!("Root vault {} is sealed", root_addr)
                    } else {
                        format!("Root vault {} is not initialized", root_addr)
                    };

                    error!("Auto-unseal dependency issue detected: {}", error_msg);

                    if let Err(e) = event_tx.send(VaultEvent::AutoUnsealDependencyError {
                        sub_addr: sub_addr.clone(),
                        root_addr: root_addr.clone(),
                        error: error_msg,
                    }) {
                        error!("Failed to send event: {}", e);
                    }

                    continue;
                }

                // Now check sub vault health
                let sub_health = match check_vault_health(&client, sub_addr).await {
                    Ok(health) => {
                        info!(
                            "Sub vault health at {}: sealed={}, initialized={}",
                            sub_addr, health.sealed, health.initialized
                        );
                        health
                    }
                    Err(e) => {
                        // Sub vault is unreachable - log but don't emit event yet
                        warn!("Sub vault {} is unreachable: {}", sub_addr, e);
                        continue;
                    }
                };

                // We've checked both vaults - now call the dependency check function
                if let Err(e) = check_auto_unseal_dependencies(
                    &client,
                    sub_addr,
                    &sub_health,
                    root_addr,
                    &root_health,
                    &event_tx,
                )
                .await
                {
                    error!("Failed to check auto-unseal dependencies: {}", e);
                }
            }

            Ok(())
        })
    }
}

// Add new message type for getting the actor's current vault address
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<String, ActorError>")]
pub struct GetCurrentAddress;

impl Handler<GetCurrentAddress> for VaultActor {
    type Result = ResponseFuture<Result<String, ActorError>>;

    fn handle(&mut self, _: GetCurrentAddress, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        async move { Ok(addr) }.boxed_local()
    }
}

// Add new message type for setting the actor's current vault address
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<(), ActorError>")]
pub struct SetCurrentAddress(pub String);

impl Handler<SetCurrentAddress> for VaultActor {
    type Result = ResponseFuture<Result<(), ActorError>>;

    fn handle(&mut self, msg: SetCurrentAddress, _ctx: &mut Context<Self>) -> Self::Result {
        self.vault_addr = msg.0;
        async move { Ok(()) }.boxed_local()
    }
}

// Add new message type for adding an unsealer relationship
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<(), ActorError>")]
pub struct AddUnsealerRelationship {
    pub sub_addr: String,
    pub root_addr: String,
}

impl Handler<AddUnsealerRelationship> for VaultActor {
    type Result = ResponseFuture<Result<(), ActorError>>;

    fn handle(&mut self, msg: AddUnsealerRelationship, _ctx: &mut Context<Self>) -> Self::Result {
        // Update the relationship in the actor instance
        self.unsealer_relationships
            .insert(msg.sub_addr.clone(), msg.root_addr.clone());

        // Log for debugging
        info!(
            "Added unsealer relationship: sub={}, root={}",
            msg.sub_addr, msg.root_addr
        );

        // Clone values for async
        let sub_addr = msg.sub_addr;
        let root_addr = msg.root_addr;
        let mut actor = self.clone();

        async move {
            // Register both vaults
            actor.register_vault(sub_addr.clone()).await;
            actor.register_vault(root_addr.clone()).await;

            // Check if the root vault has any issues
            if let Ok(root_status) = actor.check_status(&root_addr).await {
                if root_status.sealed || !root_status.initialized {
                    info!("Detected issue with root vault: sealed={}, init={}",
                              root_status.sealed, root_status.initialized);

                    // Construct error message
                    let error_msg = if root_status.sealed {
                        format!("Sub vault at {} cannot auto-unseal because root vault at {} is sealed",
                               sub_addr, root_addr)
                    } else {
                        format!("Sub vault at {} cannot auto-unseal because root vault at {} is not initialized",
                               sub_addr, root_addr)
                    };

                    // Emit error event
                    if let Some(sender) = &actor.event_sender {
                        let _ = sender.send(VaultEvent::AutoUnsealDependencyError {
                            sub_addr: sub_addr.clone(),
                            root_addr: root_addr.clone(),
                            error: error_msg.clone(),
                        });

                        // Also send general error
                        let _ = sender.send(VaultEvent::Error(error_msg));
                    }
                }
            }

            Ok(())
        }
        .boxed_local()
    }
}

// Add new message type for explicitly registering a vault
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<(), ActorError>")]
pub struct RegisterVault(pub String);

impl Handler<RegisterVault> for VaultActor {
    type Result = ResponseFuture<Result<(), ActorError>>;

    fn handle(&mut self, msg: RegisterVault, _ctx: &mut Context<Self>) -> Self::Result {
        // Clone for async to avoid borrowing issues
        let addr = msg.0;
        let mut actor = self.clone();

        async move {
            // Register the vault
            actor.register_vault(addr.clone()).await;
            info!("Registered vault: {}", addr);
            Ok(())
        }
        .boxed_local()
    }
}

/// Message to seal a vault intentionally
#[derive(Message)]
#[rtype(result = "Result<(), ActorError>")]
pub struct SealVault {
    pub token: String,
}

impl Handler<SealVault> for VaultActor {
    type Result = ResponseFuture<Result<(), ActorError>>;

    fn handle(&mut self, msg: SealVault, _ctx: &mut Self::Context) -> Self::Result {
        let address = self.vault_addr.clone();
        let token = msg.token.clone();
        let event_sender = self.event_sender.clone();

        Box::pin(async move {
            info!("Sealing vault at {}", address);

            match crate::vault::seal_vault(&address, &token).await {
                Ok(_) => {
                    info!("Successfully sealed vault at {}", address);

                    // Send an event if applicable
                    if let Some(sender) = &event_sender {
                        let _ = sender.send(VaultEvent::Error(format!(
                            "Vault at {} was intentionally sealed",
                            address
                        )));
                    }

                    Ok(())
                }
                Err(err) => {
                    error!("Failed to seal vault: {}", err);

                    if let Some(sender) = &event_sender {
                        let _ = sender.send(VaultEvent::Error(format!(
                            "Failed to seal vault at {}: {}",
                            address, err
                        )));
                    }

                    Err(ActorError::VaultApi(format!(
                        "Failed to seal vault: {}",
                        err
                    )))
                }
            }
        })
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
        debug!(
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

        debug!("Successfully obtained unwrapped transit token");

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
