use actix::*;
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use env_logger::Env;
use futures_util::stream::StreamExt;
use log::{debug, error, info};
use merka_vault::actor::{
    AddUnsealerRelationship, AutoUnseal, CheckDependencies, CheckStatus, GetCurrentAddress,
    InitVault, RegisterVault, SealVault, SetCurrentAddress, SetupPki, UnsealVault, VaultActor,
    VaultEvent,
};
use serde::{Deserialize, Serialize};
use socketioxide::{
    extract::{Data, SocketRef},
    socket::DisconnectReason,
    SocketIo,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;

// Request and Response structs
#[derive(Deserialize)]
struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Deserialize)]
struct UnsealRequest {
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct SealRequest {
    token: String,
}

#[derive(Deserialize)]
struct SetupPkiRequest {
    role_name: String,
    common_name: String,
    ttl: String,
}

#[derive(Deserialize)]
struct RegisterVaultRequest {
    addr: String,
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

// Initialize vault
async fn init_vault(state: web::Data<AppState>, req: web::Json<InitRequest>) -> impl Responder {
    let result = state
        .actor
        .send(InitVault {
            secret_shares: req.secret_shares,
            secret_threshold: req.secret_threshold,
        })
        .await;

    match result {
        Ok(r) => match r {
            Ok(keys) => HttpResponse::Ok().json(ApiResponse {
                success: true,
                data: Some(keys),
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

// Setup PKI
async fn setup_pki(state: web::Data<AppState>, req: web::Json<SetupPkiRequest>) -> impl Responder {
    let result = state
        .actor
        .send(SetupPki {
            role_name: req.role_name.clone(),
        })
        .await;

    match result {
        Ok(r) => match r {
            Ok(result) => HttpResponse::Ok().json(ApiResponse::<String> {
                success: true,
                data: Some(format!("{:?}", result)),
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

// Auto unseal
async fn auto_unseal(state: web::Data<AppState>) -> impl Responder {
    let result = state.actor.send(AutoUnseal).await;

    match result {
        Ok(r) => match r {
            Ok(result) => HttpResponse::Ok().json(ApiResponse::<String> {
                success: true,
                data: Some(format!("{:?}", result)),
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

// Socket.IO event handler
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
                    .route("/initialize", web::post().to(init_vault))
                    .route("/unseal", web::post().to(unseal_vault))
                    .route("/status", web::get().to(check_status))
                    .route("/setup_pki", web::post().to(setup_pki))
                    .route("/autounseal", web::post().to(auto_unseal)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
