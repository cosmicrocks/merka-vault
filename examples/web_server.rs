/// # Merka Vault Web Server
///
/// This example demonstrates a complete web server implementation for managing Vault instances
/// with the following capabilities:
///
/// - Vault initialization and unsealing
/// - Transit-based auto-unseal setup
/// - PKI infrastructure configuration
/// - WebSocket events for real-time operation status
/// - RESTful API for all vault operations
///
/// ## Operation Sequence
///
/// For proper vault setup, operations should follow this sequence:
///
/// 1. Initialize root vault (`/api/setup_root` or `/api/init`)
/// 2. Unseal root vault (`/api/unseal`) if not done in step 1
/// 3. Setup transit engine (`/api/setup_transit`) if not done in step 1
/// 4. Generate transit token (`/api/generate_transit_token`)
/// 5. Restart sub vault with transit token
/// 6. Initialize sub vault with auto-unseal (`/api/setup_sub_vault` or `/api/auto_unseal`)
/// 7. Setup PKI in sub vault (part of `/api/setup_sub_vault`)
///
/// ## API Endpoints
///
/// - `POST /api/setup_root` - Full root vault initialization, unsealing, and transit setup
/// - `POST /api/init` - Initialize a vault instance
/// - `POST /api/unseal` - Unseal a vault instance
/// - `POST /api/setup_transit` - Set up the transit engine
/// - `POST /api/generate_transit_token` - Generate a token for transit auto-unseal
/// - `POST /api/setup_sub_vault` - Set up a sub vault with auto-unseal and PKI
/// - `POST /api/auto_unseal` - Configure auto-unseal only
/// - `GET /api/status` - Check vault status
use actix::*;
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use env_logger::Env;
use futures_util::stream::StreamExt;
use log::{debug, error, info, warn};
use merka_vault::actor::{
    AddUnsealerRelationship, AutoUnseal, CheckDependencies, CheckStatus, GetCurrentAddress,
    GetUnwrappedTransitToken, InitVault, SetCurrentAddress, SetupPki, SetupTransit, UnsealVault,
    VaultActor, VaultEvent,
};
use serde::{Deserialize, Serialize};
use socketioxide::{extract::SocketRef, socket::DisconnectReason, SocketIo};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;

// Request and Response structs
#[derive(Deserialize)]
#[allow(dead_code)]
struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Deserialize)]
struct UnsealRequest {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SealRequest {
    token: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SetupPkiRequest {
    role_name: String,
    common_name: String,
    ttl: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RegisterVaultRequest {
    addr: String,
}

#[derive(Deserialize)]
struct SetupRootRequest {
    root_addr: String,
    secret_shares: u8,
    secret_threshold: u8,
    key_name: String,
    token: Option<String>,
}

#[derive(Deserialize)]
struct SetupSubRequest {
    sub_addr: String,
    domain: String,
    ttl: String,
    root_addr: String,
    root_token: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SetupTransitRequest {
    key_name: String,
    token: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GenerateWrappedTokenRequest {
    policy_name: String,
    wrap_ttl: String,
    token: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct UnwrapTokenRequest {
    wrapped_token: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AddUnsealerRelationshipRequest {
    sub_addr: String,
    root_addr: String,
    key_name: String,
}

#[derive(Deserialize)]
struct GetTransitTokenRequest {
    root_addr: String,
    root_token: String,
    key_name: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

// For handling socket.io connections
struct AppState {
    actor: Addr<VaultActor>,
    event_tx: broadcast::Sender<VaultEvent>,
    connections: Arc<Mutex<HashMap<String, SocketRef>>>,
}

// Define the VaultCredentials struct
#[derive(Serialize, Deserialize, Default)]
struct VaultCredentials {
    // Root vault credentials
    root_unseal_keys: Vec<String>,
    root_token: String,
    // Sub vault credentials
    sub_token: String,
    // Transit token for auto-unseal
    transit_token: String,
}

// Unseal vault
async fn unseal_vault(state: web::Data<AppState>, req: web::Json<UnsealRequest>) -> impl Responder {
    let result = state
        .actor
        .send(UnsealVault {
            keys: req.keys.clone(),
        })
        .await;

    match result {
        Ok(r) => match r {
            Ok(unsealed) => HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(unsealed),
                error: None,
            }),
            Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        },
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

// Check vault status
async fn check_status(state: web::Data<AppState>) -> impl Responder {
    let result = state.actor.send(CheckStatus).await;

    match result {
        Ok(r) => match r {
            Ok(status) => HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(status),
                error: None,
            }),
            Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        },
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

/// Socket.IO event handler for vault operation events
///
/// Emits real-time events to connected clients
fn socket_handler(socket: SocketRef, app_state: web::Data<AppState>) {
    info!("Socket connected: {}", socket.id);

    // Store connection
    let socket_id = socket.id.to_string();
    let socket_ref = socket.clone();
    let connections = app_state.connections.clone();

    tokio::spawn(async move {
        let mut connections = connections.lock().await;
        connections.insert(socket_id, socket_ref);
    });

    // Create a clone of socket_id for the disconnect handler
    let socket_id_clone = socket.id.to_string();
    let app_state_clone = app_state.clone();

    // Handle disconnect
    socket.on_disconnect(move |reason: DisconnectReason| {
        info!(
            "Socket disconnected: {}, reason: {:?}",
            socket_id_clone, reason
        );
        let connections = app_state_clone.connections.clone();

        tokio::spawn(async move {
            let mut connections = connections.lock().await;
            connections.remove(&socket_id_clone);
        });
    });

    // Subscribe to actor events
    let event_rx = app_state.event_tx.subscribe();
    let socket_clone = socket.clone();

    tokio::spawn(async move {
        let mut stream = BroadcastStream::new(event_rx);

        while let Some(Ok(event)) = stream.next().await {
            match &event {
                VaultEvent::Initialized { .. } => {
                    info!("Emitting initialized event");
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("initialized", &json).ok();
                    }
                }
                VaultEvent::Unsealed { .. } => {
                    info!("Emitting unsealed event");
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("unsealed", &json).ok();
                    }
                }
                VaultEvent::PkiSetupComplete { .. } => {
                    info!("Emitting pki_setup_complete event");
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("pki_setup_complete", &json).ok();
                    }
                }
                VaultEvent::AutounsealComplete { .. } => {
                    info!("Emitting autounseal_complete event");
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("autounseal_complete", &json).ok();
                    }
                }
                VaultEvent::StatusChecked { .. } => {
                    debug!("Emitting status_checked event");
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("status_checked", &json).ok();
                    }
                }
                VaultEvent::VaultHealthUpdated { .. } => {
                    debug!("Emitting vault_health_updated event");
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("vault_health_updated", &json).ok();
                    }
                }
                VaultEvent::Error(err) => {
                    error!("Emitting error event: {}", err);
                    let error_json = serde_json::json!({ "error": err.to_string() });
                    if let Ok(json) = serde_json::to_string(&error_json) {
                        socket_clone.emit("error", &json).ok();
                    }
                }
                _ => {
                    debug!("Emitting other event: {:?}", event);
                    if let Ok(json) = serde_json::to_string(&event) {
                        socket_clone.emit("event", &json).ok();
                    }
                }
            }
        }
    });
}

// List vaults
async fn list_vaults(state: web::Data<AppState>) -> impl Responder {
    // Get current address
    let current_addr = match state.actor.send(GetCurrentAddress).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to get vault address: {}", e)),
            });
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            })
        }
    };

    // Return list of known vaults
    let root_vault = current_addr;

    // Try to check status of the root vault
    let root_status = match state.actor.send(CheckStatus).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            })
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            })
        }
    };

    // Create a response with the vault info
    let vault_info = serde_json::json!({
        "vaults": [{
            "address": root_vault,
            "type": "root",
            "status": {
                "initialized": root_status.initialized,
                "sealed": root_status.sealed,
                "standby": root_status.standby
            }
        }]
    });

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(vault_info),
        error: None,
    })
}

// Setup wizard
async fn setup(_state: web::Data<AppState>) -> impl Responder {
    // This would be a non-interactive version of the setup wizard
    // Since the CLI version is interactive, we'll provide a placeholder implementation
    HttpResponse::Ok().json(ApiResponse::<String> {
        success: true,
        data: Some("Setup wizard API endpoint implemented as placeholder. Use /setup_root and /setup_sub separately for non-interactive setup.".to_string()),
        error: None,
    })
}

/// Setup a root vault with initialization, unsealing, and transit engine setup
///
/// This endpoint combines multiple operations for convenience:
/// 1. Initializes the vault if not already initialized
/// 2. Unseals the vault
/// 3. Sets up the transit engine for auto-unsealing
///
/// If the vault is already initialized, it will use the provided token
/// from the request to authenticate and proceed with unsealing and
/// transit engine setup.
async fn setup_root_vault(
    state: web::Data<AppState>,
    req: web::Json<SetupRootRequest>,
) -> impl Responder {
    // First set the current address to the root address
    let set_addr_result = state
        .actor
        .send(SetCurrentAddress(req.root_addr.clone()))
        .await;

    if let Err(e) = set_addr_result {
        return HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e.to_string()),
        });
    }

    // Check vault status to see if it's already initialized
    let status_result = state.actor.send(CheckStatus).await;
    let is_initialized = match status_result {
        Ok(Ok(status)) => status.initialized,
        Ok(Err(e)) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to check vault status: {}", e)),
            });
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            });
        }
    };

    // Variables to store initialization results
    let mut keys = None;
    #[allow(unused_assignments)]
    let mut root_token = String::new();

    // Initialize the vault if not already initialized
    if !is_initialized {
        let init_result = state
            .actor
            .send(InitVault {
                secret_shares: req.secret_shares,
                secret_threshold: req.secret_threshold,
            })
            .await;

        // Handle the initialization result
        match init_result {
            Ok(Ok(init_keys)) => {
                info!("Vault initialized successfully");
                // Store the keys and root token from the initialization
                keys = Some(init_keys.keys_base64.clone());
                root_token = init_keys.root_token.clone();

                // After initialization, we need to unseal the vault
                info!("Unsealing the vault with initialization keys");
                let unseal_result = state
                    .actor
                    .send(UnsealVault {
                        keys: init_keys.keys.clone(),
                    })
                    .await;

                match unseal_result {
                    Ok(Ok(unseal_status)) => {
                        if !unseal_status.sealed {
                            info!("Vault successfully unsealed");
                        } else {
                            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                                success: false,
                                data: None,
                                error: Some(format!(
                                    "Vault is still sealed after unseal attempt: progress={}",
                                    unseal_status.progress
                                )),
                            });
                        }
                    }
                    Ok(Err(e)) => {
                        return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                            success: false,
                            data: None,
                            error: Some(format!("Failed to unseal vault: {}", e)),
                        });
                    }
                    Err(e) => {
                        return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                            success: false,
                            data: None,
                            error: Some(format!("Error sending unseal request: {}", e)),
                        });
                    }
                }
            }
            Ok(Err(e)) => {
                return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to initialize vault: {}", e)),
                });
            }
            Err(e) => {
                return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(e.to_string()),
                });
            }
        }
    } else {
        // If vault is already initialized, check if it's sealed
        info!("Vault already initialized, checking if it's sealed");

        // For an already initialized vault, we need the token from somewhere
        // In a real application, this would be securely stored or provided by the user
        // For this example, we'll assume it's provided in the request if vault is already initialized
        if let Some(token) = req.token.clone() {
            info!("Using provided token for already initialized vault");
            root_token = token;
        } else {
            return HttpResponse::BadRequest().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Vault is already initialized but no token was provided".to_string()),
            });
        }
    }

    // Setup transit engine with the key name
    let setup_transit_result = state
        .actor
        .send(SetupTransit {
            key_name: req.key_name.clone(),
            token: root_token.clone(),
        })
        .await;

    match setup_transit_result {
        Ok(Ok(_)) => {
            info!("Transit engine setup successfully");
        }
        Ok(Err(e)) => {
            if e.to_string().contains("already exists") {
                info!("Transit engine already setup, continuing");
            } else {
                return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to setup transit engine: {}", e)),
                });
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            });
        }
    }

    // Create and return a response with real data
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "root_token": root_token,
            "keys": keys,
            "message": "Root vault setup completed successfully"
        })),
        error: None,
    })
}

/// Setup a sub vault with auto-unseal and PKI infrastructure
///
/// This endpoint combines multiple operations for sub vault setup:
/// 1. Initializes the sub vault with auto-unseal configuration
/// 2. Sets up PKI infrastructure for certificate issuance
///
/// The transit token must already be configured in the sub vault
/// environment before this operation.
async fn setup_sub_vault(
    state: web::Data<AppState>,
    req: web::Json<SetupSubRequest>,
) -> impl Responder {
    // API request has validated inputs - extract them
    let root_addr = req.root_addr.clone();
    let sub_addr = req.sub_addr.clone();
    let _domain = req.domain.clone();
    let _ttl = req.ttl.clone();
    let _root_token = req.root_token.clone();

    // Reset actor to sub vault
    if let Err(e) = state.actor.send(SetCurrentAddress(sub_addr.clone())).await {
        return HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to set sub vault address: {}", e)),
        });
    }

    // STEP 1: Initialize sub-vault with auto unseal
    let auto_unseal_result = match state.actor.send(AutoUnseal {}).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to auto-unseal sub vault: {}", e)),
            });
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            });
        }
    };

    let sub_token = auto_unseal_result.root_token.clone();

    // STEP 2: Setup PKI using the actor's SetupPki message with the sub vault token
    // First, we need to set the root token in the actor to the sub vault token
    if let Err(e) = state
        .actor
        .send(UnsealVault {
            keys: vec![sub_token.clone()],
        })
        .await
    {
        return HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to unseal sub vault: {}", e)),
        });
    }

    // Now set up PKI with the role name and domain
    let role_name = "merka";
    let pki_result = match state
        .actor
        .send(SetupPki {
            role_name: role_name.to_string(),
        })
        .await
    {
        Ok(Ok(pki_result)) => pki_result,
        Ok(Err(e)) => {
            // PKI setup failed, but we've still initialized the vault
            // Return partial success with the error message
            return HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(serde_json::json!({
                    "sub_token": sub_token,
                    "recovery_keys": auto_unseal_result.recovery_keys,
                    "warning": format!("PKI setup failed: {}", e)
                })),
                error: None,
            });
        }
        Err(e) => {
            // Actor communication failed
            return HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to setup PKI: {}", e)),
            });
        }
    };

    // Log the successful PKI setup
    info!("PKI setup successful, role: {}", pki_result.role_name);

    // Add relationship between sub vault and root vault
    if let Err(e) = state
        .actor
        .send(AddUnsealerRelationship {
            sub_addr: sub_addr.clone(),
            root_addr: root_addr.clone(),
        })
        .await
    {
        // This is a warning, not a fatal error as the main setup was successful
        warn!("Failed to add unsealer relationship: {}", e);
    }

    // Return success with the sub vault token and recovery keys
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "sub_token": sub_token,
            "recovery_keys": auto_unseal_result.recovery_keys,
            "pki_role_name": pki_result.role_name,
            "pki_cert_chain": pki_result.cert_chain
        })),
        error: None,
    })
}

// Get a transit token for auto-unseal
async fn get_transit_token(
    state: web::Data<AppState>,
    req: web::Json<GetTransitTokenRequest>,
) -> impl Responder {
    // Use the actor message to get an unwrapped transit token
    let transit_token_result = state
        .actor
        .send(GetUnwrappedTransitToken {
            root_addr: req.root_addr.clone(),
            root_token: req.root_token.clone(),
            key_name: req.key_name.clone(),
        })
        .await;

    match transit_token_result {
        Ok(Ok(token)) => {
            info!("Successfully obtained transit token for auto-unseal");

            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(serde_json::json!({
                    "token": token,
                    "message": "Transit token retrieved successfully"
                })),
                error: None,
            })
        }
        Ok(Err(e)) => {
            error!("Failed to get transit token: {}", e);

            HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(format!("Failed to get transit token: {}", e)),
            })
        }
        Err(e) => {
            error!("Actor error when getting transit token: {}", e);

            HttpResponse::InternalServerError().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(e.to_string()),
            })
        }
    }
}

/// Main application entry point
///
/// Starts the web server with the following components:
/// - RESTful API for vault operations
/// - Socket.IO server for real-time events
/// - Event stream for actor system events
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    info!("Starting Merka Vault example web server");
    info!("This example assumes you have started the docker-compose vaults");
    info!("Run with: `docker-compose up -d`");

    // Create vault actor with broadcast channel
    let (actor, event_rx) =
        merka_vault::actor::start_vault_actor_with_channel("http://127.0.0.1:8200");

    // Create a sender from the receiver
    let (event_tx, _) = broadcast::channel(100);

    // Subscribe to the original event_rx in a separate task
    let event_tx_clone = event_tx.clone();
    tokio::spawn(async move {
        let mut rx = event_rx;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let _ = event_tx_clone.send(event);
                }
                Err(_) => break,
            }
        }
    });

    // Set up shared state
    let app_state = web::Data::new(AppState {
        actor,
        event_tx,
        connections: Arc::new(Mutex::new(HashMap::new())),
    });

    // Start actor monitoring
    app_state.actor.do_send(CheckDependencies);

    // Create a SocketIo instance
    let io = SocketIo::builder()
        .ping_timeout(Duration::from_secs(20))
        .ping_interval(Duration::from_secs(5))
        .build_svc()
        .1; // Take the second item from the tuple, which is the SocketIo instance

    // Set up connection handler
    let app_state_clone = app_state.clone();
    io.ns(
        "/",
        move |socket: SocketRef, _: socketioxide::extract::Data<()>| {
            socket_handler(socket, app_state_clone.clone());
        },
    );

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&app_state))
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            .service(
                web::scope("/api")
                    // Routes matching CLI Commands directly
                    .route("/list", web::get().to(list_vaults))
                    .route("/unseal", web::post().to(unseal_vault))
                    .route("/status", web::get().to(check_status))
                    .route("/setup", web::post().to(setup))
                    .route("/setup_root", web::post().to(setup_root_vault))
                    .route("/setup_sub", web::post().to(setup_sub_vault))
                    .route("/get_transit_token", web::post().to(get_transit_token)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
