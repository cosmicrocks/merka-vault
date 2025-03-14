use actix::prelude::*;
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

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
    Error(String),
}

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

/// Mark the message type with Clone.
#[derive(Message, Debug, Clone)]
#[rtype(result = "Result<crate::vault::InitResult, crate::vault::VaultError>")]
pub struct InitVault {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

impl Handler<InitVault> for VaultActor {
    type Result = ResponseFuture<Result<crate::vault::InitResult, crate::vault::VaultError>>;

    fn handle(&mut self, msg: InitVault, _ctx: &mut Context<Self>) -> Self::Result {
        let addr = self.vault_addr.clone();
        let event_sender = self.event_sender.clone();

        async move {
            match crate::vault::init::init_vault(
                &addr,
                msg.secret_shares,
                msg.secret_threshold,
                None,
                None,
            )
            .await
            {
                Ok(init_resp) => {
                    if let Some(sender) = event_sender {
                        let _ = sender.send(VaultEvent::Initialized {
                            root_token: init_resp.root_token.clone(),
                            keys: init_resp.keys.clone(),
                        });
                    }
                    Ok(init_resp)
                }
                Err(err) => {
                    // Publish an error event so tests won't hang
                    if let Some(sender) = event_sender {
                        let _ = sender.send(VaultEvent::Error(format!("{}", err)));
                    }
                    Err(err)
                }
            }
        }
        .boxed_local()
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
