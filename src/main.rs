// main.rs — Axum REST API 入口
// 暴露以下接口：
//   GET  /keys              — 生成临时测试密钥对
//   GET  /chain             — 获取完整链数据
//   POST /encrypt_and_mine  — 加密并上链
//   POST /redact            — 合规修订（陷门碰撞）
//   GET  /                  — 前端页面（静态文件）

mod crypto;
mod chain;
mod faest_ffi;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chain::{Blockchain, EncryptedPayload, Transaction};
use crypto::{
    ChameleonHash, FaestImpl, PqSignature,
    envelope_encrypt, generate_faest_keypair, generate_rsa_keypair,
};
use crypto::EnvelopeResult;
use crypto::envelope_decrypt;
use axum::extract::Path;
use rsa::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// ────────────────────────────────────────────────────────────────────────────
// § 1  共享应用状态
// ────────────────────────────────────────────────────────────────────────────

/// 全局共享状态：包含变色龙哈希参数和区块链实例。
struct AppState {
    /// 变色龙哈希系统（Admin RSA 密钥派生，内含陷门私钥指数 d）
    ch: ChameleonHash,
    /// 区块链
    chain: RwLock<Blockchain>,
    /// Admin RSA 公钥（用于加密上链内容）
    admin_rsa_pub: rsa::RsaPublicKey,
    /// Admin RSA 私钥（用于示例解密与后台合规修订）
    admin_rsa_priv: rsa::RsaPrivateKey,
}

// ────────────────────────────────────────────────────────────────────────────
// § 2  请求 / 响应数据结构
// ────────────────────────────────────────────────────────────────────────────

/// POST /encrypt_and_mine 请求体
#[derive(Deserialize)]
struct EncryptAndMineRequest {
    /// 待加密的明文内容
    plaintext: String,
    /// 发送者 FAEST 私钥，Base64 编码
    sender_private_key: String,
    /// 发送者 FAEST 公钥，Base64 编码
    sender_public_key: String,
}

/// POST /redact 请求体
#[derive(Deserialize)]
struct RedactRequest {
    /// 要修订的区块索引
    block_index: usize,
    /// 合规删除标记文本（默认："【已合规抹除】"）
    redaction_label: Option<String>,
}

/// GET /keys 响应体（FAEST 密钥对示例）
#[derive(Serialize)]
struct KeysResponse {
    /// FAEST 签名私钥，Base64 编码
    faest_private_key: String,
    /// FAEST 验证公钥，Base64 编码
    faest_public_key: String,
    /// RSA-2048 公钥（仅供参考，实际加密使用服务器 Admin 公钥）
    rsa_public_key_pem: String,
}

/// 统一错误响应
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// 将错误转为 HTTP 500 响应
fn internal_error(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: e.to_string(),
        }),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// § 3  路由处理函数
// ────────────────────────────────────────────────────────────────────────────

/// GET /keys — 生成并返回临时测试 FAEST 密钥对（每次随机生成）。
async fn get_keys() -> impl IntoResponse {
    let (fa_priv, fa_pub) = generate_faest_keypair();
    // 为前端提供一个示例 RSA 公钥（仅展示用）
    let rsa_pub_pem = match generate_rsa_keypair() {
        Ok((_, pub_key)) => match pub_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF) {
            Ok(pem) => pem,
            Err(e) => return internal_error(e).into_response(),
        },
        Err(e) => return internal_error(e).into_response(),
    };

    Json(KeysResponse {
        faest_private_key: B64.encode(&fa_priv),
        faest_public_key: B64.encode(&fa_pub),
        rsa_public_key_pem: rsa_pub_pem,
    })
    .into_response()
}

/// GET /faest_keys — 生成并返回 FAEST 密钥对（Base64 编码）
async fn get_faest_keys() -> impl IntoResponse {
    match crate::faest_ffi::keygen() {
        Ok((pk, sk)) => Json(serde_json::json!({
            "faest_public_key": B64.encode(&pk),
            "faest_private_key": B64.encode(&sk),
        })).into_response(),
        Err(e) => internal_error(format!("FAEST keygen failed: {}", e)).into_response(),
    }
}

/// GET /chain — 返回当前完整区块链数据（JSON 格式），包含链完整性验证结果。
async fn get_chain(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let chain = state.chain.read().await;
    let is_valid = chain.verify_chain(&state.ch);
    Json(serde_json::json!({
        "blocks": chain.blocks,
        "is_valid": is_valid,
        "length": chain.blocks.len()
    }))
    .into_response()
}

/// POST /encrypt_and_mine — 数字信封加密 + 签名 + 打包上链。
async fn encrypt_and_mine(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EncryptAndMineRequest>,
) -> impl IntoResponse {
    // 解码发送者密钥
    let sender_priv = match B64.decode(&req.sender_private_key) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("私钥 Base64 解码失败: {}", e)).into_response(),
    };
    let sender_pub = match B64.decode(&req.sender_public_key) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("公钥 Base64 解码失败: {}", e)).into_response(),
    };

    // 数字信封加密（使用 Admin RSA 公钥，使 Admin 可解密）
    let envelope_result = match envelope_encrypt(req.plaintext.as_bytes(), &state.admin_rsa_pub) {
        Ok(r) => r,
        Err(e) => return internal_error(e).into_response(),
    };

    let payload = EncryptedPayload {
        ciphertext: B64.encode(&envelope_result.ciphertext),
        nonce: B64.encode(&envelope_result.nonce),
        encrypted_key: B64.encode(&envelope_result.encrypted_key),
    };

    // 对 Payload 进行 FAEST 签名（身份认证）
    let signer = FaestImpl;
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let sig = match PqSignature::sign(&signer, &payload_bytes, &sender_priv) {
        Ok(s) => s,
        Err(e) => return internal_error(e).into_response(),
    };

    let tx = Transaction {
        tx_id: new_uuid(),
        payload,
        sender_signature: B64.encode(&sig),
        sender_pub_key: B64.encode(&sender_pub),
    };

    // 打包上链（内含签名验证）
    let mut chain = state.chain.write().await;
    match chain.add_block(&state.ch, tx) {
        Ok(_) => {
            let new_block = chain.blocks.last().cloned();
            Json(serde_json::json!({
                "success": true,
                "message": "交易已成功打包上链",
                "block": new_block
            }))
            .into_response()
        }
        Err(e) => internal_error(e).into_response(),
    }
}

/// POST /redact — Admin 合规修订：利用陷门替换 Payload，区块 Hash 保持不变。
async fn redact_block(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedactRequest>,
) -> impl IntoResponse {
    let label = req
        .redaction_label
        .unwrap_or_else(|| "【已合规抹除】".to_string());

    let mut chain = state.chain.write().await;
    let original_hash = chain
        .blocks
        .get(req.block_index)
        .map(|b| b.hash.clone())
        .unwrap_or_default();

    match chain.redact_block(req.block_index, &state.ch, &label) {
        Ok(_) => {
            let updated_block = chain.blocks.get(req.block_index).cloned();
            Json(serde_json::json!({
                "success": true,
                "message": format!("区块 {} 已合规修订，区块哈希保持不变", req.block_index),
                "original_hash": original_hash,
                "block": updated_block
            }))
            .into_response()
        }
        Err(e) => internal_error(e).into_response(),
    }
}

/// GET / — 返回前端页面
async fn serve_index() -> impl IntoResponse {
    let html = include_str!("../static/index.html");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(html.to_owned())
        .unwrap()
}

/// GET /block_plain/:index — 使用 Admin 私钥解密指定区块的数字信封并返回明文（Base64 与可能的 UTF-8 文本）
async fn get_block_plain(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> impl IntoResponse {
    let chain = state.chain.read().await;
    let block = match chain.blocks.get(index) {
        Some(b) => b.clone(),
        None => return (StatusCode::NOT_FOUND, Json(ErrorResponse{ error: format!("区块 {} 不存在", index) } )).into_response(),
    };

    // 从 Block 中恢复 EnvelopeResult
    let ciphertext = match B64.decode(&block.tx.payload.ciphertext) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("payload ciphertext 解码失败: {}", e)).into_response(),
    };
    let nonce = match B64.decode(&block.tx.payload.nonce) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("nonce 解码失败: {}", e)).into_response(),
    };
    let encrypted_key = match B64.decode(&block.tx.payload.encrypted_key) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("encrypted_key 解码失败: {}", e)).into_response(),
    };

    let envelope = EnvelopeResult {
        ciphertext,
        nonce,
        encrypted_key,
    };

    match envelope_decrypt(&envelope, &state.admin_rsa_priv) {
        Ok(plain_bytes) => {
            // 尝试 UTF-8 解码
            let plain_utf8 = String::from_utf8(plain_bytes.clone()).ok();
            Json(serde_json::json!({
                "success": true,
                "plaintext_base64": B64.encode(&plain_bytes),
                "plaintext_utf8": plain_utf8,
                "block_index": index,
            })) .into_response()
        }
        Err(e) => internal_error(e).into_response(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// § 4  辅助函数
// ────────────────────────────────────────────────────────────────────────────

fn new_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        (u16::from_be_bytes(bytes[6..8].try_into().unwrap()) & 0x0fff) | 0x4000,
        (u16::from_be_bytes(bytes[8..10].try_into().unwrap()) & 0x3fff) | 0x8000,
        {
            let b = &bytes[10..16];
            ((b[0] as u64) << 40)
                | ((b[1] as u64) << 32)
                | ((b[2] as u64) << 24)
                | ((b[3] as u64) << 16)
                | ((b[4] as u64) << 8)
                | (b[5] as u64)
        }
    )
}

// ────────────────────────────────────────────────────────────────────────────
// § 5  主函数
// ────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化 Admin RSA 密钥对（变色龙哈希参数来源）
    println!("🔑 正在生成 Admin RSA-2048 密钥对（用于变色龙哈希陷门）...");
    let (admin_rsa_priv, admin_rsa_pub) = generate_rsa_keypair()?;
    let ch = ChameleonHash::setup(&admin_rsa_priv);
    println!("✅ 密钥生成完成");

    // 初始化区块链并生成创世块（使用 FAEST 密钥作为创世签名示例）
    println!("⛓  正在初始化区块链并生成创世块...");
    let (genesis_priv, genesis_pub) = generate_faest_keypair();
    let mut blockchain = Blockchain::new();
    blockchain.genesis_block(&ch, &admin_rsa_pub, &genesis_priv, &genesis_pub)?;
    println!("✅ 创世块已生成，链长度: {}", blockchain.blocks.len());

    let state = Arc::new(AppState {
        ch,
        chain: RwLock::new(blockchain),
        admin_rsa_pub,
        admin_rsa_priv: admin_rsa_priv,
    });

    // 配置路由
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/keys", get(get_keys))
        .route("/faest_keys", get(get_faest_keys))
        .route("/chain", get(get_chain))
        .route("/block_plain/:index", get(get_block_plain))
        .route("/encrypt_and_mine", post(encrypt_and_mine))
        .route("/redact", post(redact_block))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    println!("🚀 服务已启动，监听 http://{}", addr);
    println!("📖 前端页面: http://localhost:8080/");
    println!("📡 API 端点:");
    println!("   GET  /keys              — 生成临时测试密钥对");
    println!("   GET  /chain             — 获取完整链数据");
    println!("   GET  /faest_keys        — 生成 FAEST 密钥对 (Base64)");
    println!("   POST /encrypt_and_mine  — 加密并上链");
    println!("   POST /redact            — 合规修订（陷门碰撞）");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

