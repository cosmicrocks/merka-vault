use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use log::info;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct InitInput {
    pub vault_addr: String,
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

#[derive(Deserialize)]
pub struct UnsealInput {
    pub vault_addr: String,
    pub keys: Vec<String>,
}

#[derive(Deserialize)]
pub struct PkiInput {
    pub vault_addr: String,
    pub domain: String,
    pub ttl: String,
    pub intermediate: bool,
    pub intermediate_addr: Option<String>,
    pub int_token: Option<String>,
}

#[derive(Deserialize)]
pub struct AutounsealInput {
    pub unsealer_addr: String,
    pub target_addr: String,
    pub token: String,
    pub key_name: String,
}

async fn init_handler(info: web::Json<InitInput>) -> impl Responder {
    match crate::api::initialize_vault_infrastructure(
        &info.vault_addr,
        "",
        crate::api::InitOptions {
            secret_shares: info.secret_shares,
            secret_threshold: info.secret_threshold,
        },
    )
    .await
    {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().body(format!("Init error: {}", e)),
    }
}

async fn unseal_handler(info: web::Json<UnsealInput>) -> impl Responder {
    match crate::api::unseal_root_vault(&info.vault_addr, info.keys.clone()).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().body(format!("Unseal error: {}", e)),
    }
}

async fn pki_handler(info: web::Json<PkiInput>) -> impl Responder {
    let token = "root"; // For simplicity.
    match crate::vault::pki::setup_pki(
        &info.vault_addr,
        token,
        &info.domain,
        &info.ttl,
        info.intermediate,
        info.intermediate_addr.as_deref(),
        info.int_token.as_deref(),
    )
    .await
    {
        Ok((cert_chain, role_name)) => HttpResponse::Ok().json(json!({
            "cert_chain": cert_chain,
            "role_name": role_name
        })),
        Err(e) => HttpResponse::InternalServerError().body(format!("PKI error: {}", e)),
    }
}

async fn autounseal_handler(info: web::Json<AutounsealInput>) -> impl Responder {
    let token = &info.token;
    let key_name = &info.key_name;
    if let Err(e) =
        crate::vault::autounseal::setup_transit_autounseal(&info.unsealer_addr, token, key_name)
            .await
    {
        return HttpResponse::InternalServerError().body(format!("Autounseal setup error: {}", e));
    }
    if let Err(e) = crate::vault::autounseal::configure_vault_for_autounseal(
        &info.target_addr,
        &info.unsealer_addr,
        token,
        key_name,
    )
    .await
    {
        return HttpResponse::InternalServerError().body(format!("Autounseal config error: {}", e));
    }
    match crate::vault::autounseal::init_with_autounseal(&info.target_addr).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().body(format!("Autounseal init error: {}", e)),
    }
}

pub async fn run_api_server_async(
    vault_addr: &str,
    _unused: &str,
    listen_addr: &str,
) -> Result<()> {
    info!("API Server running at http://{}", listen_addr);
    HttpServer::new(move || {
        App::new()
            .service(web::resource("/api/init").route(web::post().to(init_handler)))
            .service(web::resource("/api/unseal").route(web::post().to(unseal_handler)))
            .service(web::resource("/api/pki").route(web::post().to(pki_handler)))
            .service(web::resource("/api/autounseal").route(web::post().to(autounseal_handler)))
    })
    .bind(listen_addr)?
    .run()
    .await?;
    Ok(())
}
