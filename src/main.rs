mod chain;
mod crypto;
mod faest_ffi;
mod handlers;
mod progress;
mod state;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tower_http::services::ServeDir;

use crypto::{ChameleonHash, generate_rsa_keypair};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let admin_pem_path = Path::new("data/admin_rsa.pem");
    if let Some(parent) = admin_pem_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let (admin_rsa_priv, admin_rsa_pub) = if admin_pem_path.exists() {
        match fs::read_to_string(admin_pem_path) {
            Ok(pem_str) => match rsa::RsaPrivateKey::from_pkcs1_pem(&pem_str) {
                Ok(privk) => {
                    let pubk = rsa::RsaPublicKey::from(&privk);
                    (privk, pubk)
                }
                Err(_) => {
                    let (p, pubk) = generate_rsa_keypair()?;
                    if let Ok(pem) = p.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
                        let _ = fs::write(admin_pem_path, pem);
                    }
                    (p, pubk)
                }
            },
            Err(_) => {
                let (p, pubk) = generate_rsa_keypair()?;
                if let Ok(pem) = p.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
                    let _ = fs::write(admin_pem_path, pem);
                }
                (p, pubk)
            }
        }
    } else {
        let (p, pubk) = generate_rsa_keypair()?;
        if let Ok(pem) = p.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
            let _ = fs::write(admin_pem_path, pem);
        }
        (p, pubk)
    };

    let ch = ChameleonHash::setup(&admin_rsa_priv);

    let chain_path = Path::new("data/chain.json").to_path_buf();
    let blockchain = if chain_path.exists() {
        match chain::Blockchain::load_from_path(&chain_path) {
            Ok(bc) => bc,
            Err(_) => {
                let (genesis_priv, genesis_pub) = crypto::generate_faest_keypair();
                let mut bc = chain::Blockchain::new();
                bc.genesis_block(&ch, &admin_rsa_pub, &genesis_priv, &genesis_pub)?;
                let _ = bc.save_to_path(&chain_path);
                bc
            }
        }
    } else {
        let (genesis_priv, genesis_pub) = crypto::generate_faest_keypair();
        let mut bc = chain::Blockchain::new();
        bc.genesis_block(&ch, &admin_rsa_pub, &genesis_priv, &genesis_pub)?;
        let _ = bc.save_to_path(&chain_path);
        bc
    };

    let state = Arc::new(AppState {
        ch,
        chain: tokio::sync::RwLock::new(blockchain),
        admin_rsa_pub,
        admin_rsa_priv,
        chain_file: chain_path,
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/health", get(|| async { (StatusCode::OK, Json(serde_json::json!({"ok": true}))) }))
        .route("/keys", get(handlers::get_keys))
        .route("/faest_keys", get(handlers::get_faest_keys))
        .route("/faest_admin_exists", get(handlers::faest_admin_exists))
        .route("/faest_admin_keys", get(handlers::get_faest_admin_keys))
        .route("/faest_admin_keys", post(handlers::post_faest_admin_keys))
        .route("/admin_rsa", get(handlers::get_admin_rsa))
        .route("/chain", get(handlers::get_chain))
        .route("/progress/:id", get(handlers::get_progress))
        .route("/redact_prepare", post(handlers::redact_prepare))
        .route("/admin_sign", post(handlers::admin_sign))
        .route("/block_plain/:index", get(handlers::get_block_plain))
        .route("/encrypt_and_mine", post(handlers::get_chain_and_mine))
        .route("/redact", post(handlers::redact_block))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    println!("🚀 服务已启动 http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn serve_index() -> impl IntoResponse {
    let html = include_str!("../static/index.html");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(html.to_string())
        .unwrap()
}
