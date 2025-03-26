use actix::*;
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use futures_util::stream::StreamExt;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use socketioxide::{extract::SocketRef, socket::DisconnectReason, SocketIo};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;

use crate::actor::{
    AddUnsealerRelationship, CheckDependencies, CheckStatus, GetCurrentAddress,
    GetUnwrappedTransitToken, RegisterVault, SetCurrentAddress, SetRootToken, SetupRoot, SetupSub,
    SyncSubToken, SyncToken, SyncTransitToken, UnsealVault, VaultActor, VaultEvent,
};
use crate::database::DatabaseManager;

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

#[derive(Deserialize)]
struct SyncTokenRequest {
    addr: String,
    token: String,
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
    match state.actor.send(CheckStatus).await {
        Ok(res) => match res {
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

// Handle socket.io connections
fn socket_handler(socket: SocketRef, app_state: web::Data<AppState>) {
    // Clone the app_state for use in closures
    let app_state_clone = app_state.clone();

    // Store the socket reference for later
    let socket_id = socket.id.to_string();
    let socket_ref = socket.clone();

    // Use tokio::task::spawn_local since we're in a LocalSet context
    tokio::task::spawn_local(async move {
        // Add the socket to our connections
        {
            let mut connections = app_state_clone.connections.lock().await;
            connections.insert(socket_id.clone(), socket_ref.clone());
            info!("Socket connected: {}", socket_id);
        }

        // Create an event stream from our broadcast channel
        let mut event_stream = BroadcastStream::new(app_state_clone.event_tx.subscribe());

        // Send initial status
        if let Ok(Ok(status)) = app_state_clone.actor.send(CheckStatus).await {
            let status_event = VaultEvent::StatusChecked {
                initialized: status.initialized,
                sealed: status.sealed,
                standby: status.standby,
            };

            if let Ok(json) = serde_json::to_string(&status_event) {
                let _ = socket_ref.emit("vault_status", &json);
            }
        }

        // Handle incoming events
        while let Some(Ok(event)) = event_stream.next().await {
            match event {
                VaultEvent::Initialized { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("vault_init", &json);
                    }
                }
                VaultEvent::Unsealed { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("vault_unseal", &json);
                    }
                }
                VaultEvent::TransitSetup { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("transit_setup", &json);
                    }
                }
                VaultEvent::PkiSetupComplete { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("pki_setup", &json);
                    }
                }
                VaultEvent::AutounsealComplete { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("auto_unseal", &json);
                    }
                }
                VaultEvent::Error(error) => {
                    let error_json = HashMap::from([("error", error)]);
                    if let Ok(json) = serde_json::to_string(&error_json) {
                        let _ = socket_ref.emit("error", &json);
                    }
                }
                VaultEvent::VaultsListed { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("vaults_listed", &json);
                    }
                }
                VaultEvent::StatusChecked { .. } => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = socket_ref.emit("vault_status", &json);
                    }
                }
                _ => {}
            }
        }
    });

    // Store socket_id for disconnect handler
    let socket_id = socket.id.to_string();
    let app_state_clone = app_state.clone();

    // Handle disconnect
    socket.on_disconnect(move |reason: DisconnectReason| {
        info!("Socket disconnected: {:?}", reason);

        tokio::task::spawn_local(async move {
            let mut connections = app_state_clone.connections.lock().await;
            connections.remove(&socket_id);
            info!("Removed socket: {}", socket_id);
        });
    });
}

// List all known vaults
async fn list_vaults(state: web::Data<AppState>) -> impl Responder {
    // Query the actor for all known vaults
    let result = state.actor.send(CheckDependencies).await;

    // After checking dependencies, we return the current known vaults
    match result {
        Ok(_) => {
            // Just return a success, the actual data will be sent via socket.io
            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(HashMap::from([("message", "Dependency check initiated")])),
                error: None,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(e.to_string()),
        }),
    }
}

// Legacy setup endpoint - redirects to setup_root
async fn setup(_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(HashMap::from([(
            "message",
            "Please use /setup_root and /setup_sub instead of this legacy endpoint",
        )])),
        error: None,
    })
}

// Root vault setup (Step 1)
async fn setup_root_vault(
    state: web::Data<AppState>,
    req: web::Json<SetupRootRequest>,
) -> impl Responder {
    // Store original address
    let current_addr = state
        .actor
        .send(GetCurrentAddress)
        .await
        .unwrap_or_else(|_| Ok(String::new()))
        .unwrap_or_default();

    // Set address to the target root vault
    let _ = state
        .actor
        .send(SetCurrentAddress(req.root_addr.clone()))
        .await;

    // If a token was provided, set it
    if let Some(token) = &req.token {
        info!("Using provided token for root vault setup");
        let _ = state.actor.send(SetRootToken(token.clone())).await;

        // No need for direct database operation - the actor will handle this
        // through the SyncToken message sent later
    }

    // Now perform the root vault setup
    let setup_result = state
        .actor
        .send(SetupRoot {
            addr: req.root_addr.clone(),
            secret_shares: req.secret_shares,
            secret_threshold: req.secret_threshold,
            key_name: req.key_name.clone(),
        })
        .await;

    // Check root token and store it
    if let Ok(Ok(unwrapped_token)) = &setup_result {
        // Check if the actor has a root token
        match state.actor.send(CheckStatus).await {
            Ok(Ok(status)) => {
                if status.initialized && !status.sealed {
                    // Use SyncToken and SyncTransitToken messages to store tokens via actor
                    if let Some(root_token) = &req.token {
                        if !root_token.is_empty() {
                            let _ = state
                                .actor
                                .send(SyncToken {
                                    addr: req.root_addr.clone(),
                                    token: root_token.clone(),
                                })
                                .await;
                        }
                    }

                    let _ = state
                        .actor
                        .send(SyncTransitToken {
                            addr: req.root_addr.clone(),
                            token: unwrapped_token.clone(),
                        })
                        .await;
                }
            }
            _ => {
                warn!("Unable to check vault status after setup to retrieve token");
            }
        }
    }

    // Restore the original address
    let _ = state.actor.send(SetCurrentAddress(current_addr)).await;

    // Return the final result to client
    match setup_result {
        Ok(Ok(unwrapped_token)) => {
            info!("Successfully set up root vault and obtained transit token");

            // Create response with the unwrapped token
            let data = HashMap::from([
                ("unwrapped_token", unwrapped_token),
                (
                    "message",
                    "Root vault setup completed successfully".to_string(),
                ),
                // Include the token if it was provided
                ("root_token", req.token.clone().unwrap_or_default()),
            ]);

            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(data),
                error: None,
            })
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Root vault setup failed: {}", e)),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Actor messaging error: {}", e)),
        }),
    }
}

// Sub vault setup (Step 2)
async fn setup_sub_vault(
    state: web::Data<AppState>,
    req: web::Json<SetupSubRequest>,
) -> impl Responder {
    // Store the sub vault and root vault relationship
    let _ = state
        .actor
        .send(AddUnsealerRelationship {
            sub_addr: req.sub_addr.clone(),
            root_addr: req.root_addr.clone(),
        })
        .await;

    // Set address to the target sub vault
    let current_addr = state
        .actor
        .send(GetCurrentAddress)
        .await
        .unwrap_or_else(|_| Ok(String::new()))
        .unwrap_or_default();

    let _ = state
        .actor
        .send(SetCurrentAddress(req.sub_addr.clone()))
        .await;

    // Now set up the sub vault using the actor message
    let setup_result = state
        .actor
        .send(SetupSub {
            root_addr: req.root_addr.clone(),
            root_token: req.root_token.clone(),
            sub_addr: req.sub_addr.clone(),
            domain: req.domain.clone(),
            ttl: req.ttl.clone(),
        })
        .await;

    // Get token and store it
    if let Ok(Ok(sub_token)) = &setup_result {
        // Use a new actor message to store sub token
        let _ = state
            .actor
            .send(SyncSubToken {
                addr: req.sub_addr.clone(),
                token: sub_token.clone(),
            })
            .await;
    }

    // Register the sub vault for monitoring
    let _ = state.actor.send(RegisterVault(req.sub_addr.clone())).await;

    // Restore the original address
    let _ = state.actor.send(SetCurrentAddress(current_addr)).await;

    // Kick off dependency check (which will notify WebSocket clients)
    let _ = state.actor.send(CheckDependencies).await;

    // Return the result
    match setup_result {
        Ok(Ok(sub_token)) => {
            // Create response with the token
            let data = HashMap::from([
                ("sub_token", sub_token),
                (
                    "message",
                    "Sub vault setup completed successfully".to_string(),
                ),
            ]);

            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(data),
                error: None,
            })
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to auto-unseal sub vault: {}", e)),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Actor messaging error: {}", e)),
        }),
    }
}

// Generate a transit token for auto-unseal
async fn get_transit_token(
    state: web::Data<AppState>,
    req: web::Json<GetTransitTokenRequest>,
) -> impl Responder {
    // Store original address
    let current_addr = state
        .actor
        .send(GetCurrentAddress)
        .await
        .unwrap_or_else(|_| Ok(String::new()))
        .unwrap_or_default();

    // Set address to the target root vault
    let _ = state
        .actor
        .send(SetCurrentAddress(req.root_addr.clone()))
        .await;

    // Get unwrapped transit token
    let token_result = state
        .actor
        .send(GetUnwrappedTransitToken {
            root_addr: req.root_addr.clone(),
            root_token: req.root_token.clone(),
            key_name: req.key_name.clone(),
        })
        .await;

    // Store the token
    if let Ok(Ok(transit_token)) = &token_result {
        info!("Successfully unwrapped transit token for auto-unseal");

        // Sync the transit token with the actor instead of direct database operations
        match state
            .actor
            .send(SyncTransitToken {
                addr: req.root_addr.clone(),
                token: transit_token.clone(),
            })
            .await
        {
            Ok(Ok(_)) => info!("Successfully synced transit token with actor"),
            Ok(Err(e)) => warn!("Failed to sync transit token with actor: {}", e),
            Err(e) => warn!("Failed to send sync transit token message to actor: {}", e),
        }
    }

    // Restore the original address
    let _ = state.actor.send(SetCurrentAddress(current_addr)).await;

    // Return the response
    match token_result {
        Ok(Ok(token)) => {
            // Create response with the token
            let data = HashMap::from([
                ("token", token),
                (
                    "message",
                    "Transit token retrieved successfully".to_string(),
                ),
            ]);

            HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(data),
                error: None,
            })
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to get transit token: {}", e)),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Actor messaging error: {}", e)),
        }),
    }
}

// Sync a known token with the database
async fn sync_token(
    state: web::Data<AppState>,
    req: web::Json<SyncTokenRequest>,
) -> impl Responder {
    // Check if this token is valid
    let current_addr = state
        .actor
        .send(GetCurrentAddress)
        .await
        .unwrap_or_else(|_| Ok(String::new()))
        .unwrap_or_default();

    // Set to the requested address
    let _ = state.actor.send(SetCurrentAddress(req.addr.clone())).await;

    // Set the token in the actor and sync with database
    let sync_result = state
        .actor
        .send(SyncToken {
            addr: req.addr.clone(),
            token: req.token.clone(),
        })
        .await;

    // Verify the token works by checking status
    let status_result = state.actor.send(CheckStatus).await;

    // Restore original address
    let _ = state.actor.send(SetCurrentAddress(current_addr)).await;

    // First check if syncing was successful
    match sync_result {
        Ok(Ok(_)) => {
            // Now check if the token is valid
            match status_result {
                Ok(Ok(status)) => {
                    if status.initialized && !status.sealed {
                        HttpResponse::Ok().json(ApiResponse {
                            success: true,
                            data: Some(HashMap::from([(
                                "message",
                                "Token successfully synced and verified working",
                            )])),
                            error: None,
                        })
                    } else {
                        HttpResponse::BadRequest().json(ApiResponse::<()> {
                            success: false,
                            data: None,
                            error: Some(format!(
                                "Token sync issue - Vault state: initialized={}, sealed={}",
                                status.initialized, status.sealed
                            )),
                        })
                    }
                }
                Ok(Err(e)) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("Token verification failed: {}", e)),
                }),
                Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("Actor messaging error: {}", e)),
                }),
            }
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Failed to sync token: {}", e)),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(format!("Actor messaging error: {}", e)),
        }),
    }
}

/// Start the web server with the specified configuration
///
/// This function initializes the web server with Socket.IO support and creates
/// a VaultActor instance to handle all Vault operations. The server only communicates
/// with the Vault through the actor, enforcing a clean architectural separation.
pub async fn start_server(
    listen_addr: &str,
    vault_addr: &str,
    db_path: &str,
) -> std::io::Result<()> {
    // Don't initialize logging here since it's already initialized in the main function
    info!("Starting Merka Vault web server");
    info!("This assumes you have started the docker-compose vaults");
    info!("Run with: `docker-compose up -d`");

    // Remove the old JSON credentials file if it exists
    if std::path::Path::new("vault_credentials.json").exists() {
        info!("Removing old vault_credentials.json file since we now use SQLite");
        if let Err(e) = std::fs::remove_file("vault_credentials.json") {
            warn!("Failed to remove old vault_credentials.json file: {}", e);
        }
    }

    // Create a SocketIo instance
    let io = SocketIo::builder()
        .ping_timeout(Duration::from_secs(20))
        .ping_interval(Duration::from_secs(5))
        .build_svc()
        .1; // Take the second item from the tuple, which is the SocketIo instance

    // Start HTTP server with a local task set for the socket.io middleware
    info!("Listening on {}", listen_addr);
    let local_set = tokio::task::LocalSet::new();

    // Create a closure to set up the HTTP server
    let http_server_setup = {
        let vault_addr = vault_addr.to_string();
        let db_path = db_path.to_string();
        let io = io.clone();

        move || {
            // Create a database manager factory for the actor
            let db_manager_factory = || -> Result<DatabaseManager, r2d2::Error> {
                let manager = DatabaseManager::new(&db_path)?;
                info!("Successfully initialized SQLite database at {}", db_path);
                Ok(manager)
            };

            // Create vault actor with broadcast channel and database inside LocalSet
            let (tx, _) = broadcast::channel(100);

            // Create the actor using the database factory, enforcing architectural constraints
            // by ensuring server code only interacts with vault through the actor
            let actor = match db_manager_factory() {
                Ok(db_manager) => crate::actor::VaultActor::new(&vault_addr, Some(tx.clone()))
                    .with_database(db_manager),
                Err(e) => {
                    error!("Failed to initialize database: {}", e);
                    // Fallback to actor without database when db init fails
                    crate::actor::VaultActor::new(&vault_addr, Some(tx.clone()))
                }
            };
            let actor_addr = actor.start();

            // Set up shared state
            let app_state = web::Data::new(AppState {
                actor: actor_addr.clone(),
                event_tx: tx,
                connections: Arc::new(Mutex::new(HashMap::new())),
            });

            // Start actor monitoring
            app_state.actor.do_send(CheckDependencies);

            // Set up connection handler
            let app_state_clone = app_state.clone();
            io.ns(
                "/",
                move |socket: SocketRef, _: socketioxide::extract::Data<()>| {
                    socket_handler(socket, app_state_clone.clone());
                },
            );

            App::new()
                .app_data(app_state)
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
                        .route("/get_transit_token", web::post().to(get_transit_token))
                        .route("/sync_token", web::post().to(sync_token)),
                )
        }
    };

    // Run the HTTP server within the LocalSet
    local_set
        .run_until(HttpServer::new(http_server_setup).bind(listen_addr)?.run())
        .await
}
