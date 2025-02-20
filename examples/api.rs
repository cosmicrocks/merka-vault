use actix::prelude::*;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use merka_vault::actor::{InitVault, VaultActor};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct InitParams {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Serialize)]
struct InitResponse {
    root_token: String,
    keys: Vec<String>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Start the VaultActor with the Vault address (adjust as needed)
    let vault_addr = "http://127.0.0.1:8200".to_string();
    let vault_actor_addr = VaultActor::new(vault_addr).start();

    // Start HTTP server and register routes
    HttpServer::new(move || {
        App::new()
            // Share the actor's address across handlers
            .app_data(web::Data::new(vault_actor_addr.clone()))
            .route("/", web::get().to(index))
            .route("/init", web::post().to(init_vault))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Vault API Proxy is running!")
}

async fn init_vault(
    vault_actor: web::Data<Addr<VaultActor>>,
    params: web::Json<InitParams>,
) -> impl Responder {
    // Create the actor message to initialize Vault
    let init_msg = InitVault {
        secret_shares: params.secret_shares,
        secret_threshold: params.secret_threshold,
    };

    // Send the message to the actor and await the result
    match vault_actor.send(init_msg).await {
        Ok(Ok(init_res)) => {
            // Convert the actor's response into a JSON response.
            let response = InitResponse {
                root_token: init_res.root_token,
                keys: init_res.keys,
            };
            HttpResponse::Ok().json(response)
        }
        Ok(Err(err)) => HttpResponse::InternalServerError().body(format!("Vault error: {}", err)),
        Err(err) => HttpResponse::InternalServerError().body(format!("Actor error: {}", err)),
    }
}
