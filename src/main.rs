// main.rs — Axum REST API 入口
// 暴露以下接口：
//   GET  /keys              — 生成临时测试密钥对
//   GET  /chain             — 获取完整链数据
//   POST /encrypt_and_mine  — 加密并上链
//   POST /redact            — 合规修订（陷门碰撞）
//   GET  /                  — 前端页面（静态文件）

mod chain;
mod crypto;
mod faest_ffi;

use std::sync::Arc;

use anyhow::Result;
use axum::extract::Path;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chain::{Blockchain, EncryptedPayload, Transaction};
use crypto::envelope_decrypt;
use crypto::EnvelopeResult;
use crypto::{
    envelope_encrypt, generate_faest_keypair, generate_rsa_keypair, ChameleonHash, FaestImpl,
    PqSignature,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

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
    /// 本地链文件路径（持久化位置）
    chain_file: std::path::PathBuf,
}

// ────────────────────────────────────────────────────────────────────────────
// § 2  请求 / 响应数据结构
// ────────────────────────────────────────────────────────────────────────────

/// POST /encrypt_and_mine 请求体
#[derive(Deserialize)]
struct EncryptAndMineRequest {
    /// 待加密的明文内容
    plaintext: String,
    /// 若为 true，则 `plaintext` 为 Base64 编码的二进制数据
    plaintext_base64: Option<bool>,
    /// 发送者 FAEST 私钥，Base64 编码
    sender_private_key: String,
    /// 发送者 FAEST 公钥，Base64 编码
    sender_public_key: String,
    /// 可选：原始文件名（若上传文件）
    filename: Option<String>,
    /// 可选：MIME 类型（若上传文件）
    mime_type: Option<String>,
}

/// POST /redact 请求体
#[derive(Deserialize)]
struct RedactRequest {
    /// 要修订的区块索引
    block_index: usize,
    /// 合规删除标记文本（默认："【已合规抹除】"）
    redaction_label: Option<String>,
    /// 管理员 FAEST 公钥（Base64）——用于节点验签
    admin_public_key: Option<String>,
    /// 管理员对本次修订操作的 FAEST 签名（Base64）
    admin_signature: Option<String>,
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
        }))
        .into_response(),
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
    // 处理 plaintext 是否为 Base64 编码二进制
    let plaintext_bytes: Vec<u8> = if req.plaintext_base64.unwrap_or(false) {
        match base64::engine::general_purpose::STANDARD.decode(&req.plaintext) {
            Ok(b) => b,
            Err(e) => {
                return internal_error(format!("plaintext Base64 解码失败: {}", e)).into_response()
            }
        }
    } else {
        req.plaintext.as_bytes().to_vec()
    };

    let envelope_result = match envelope_encrypt(&plaintext_bytes, &state.admin_rsa_pub) {
        Ok(r) => r,
        Err(e) => return internal_error(e).into_response(),
    };

    let payload = EncryptedPayload {
        ciphertext: B64.encode(&envelope_result.ciphertext),
        nonce: B64.encode(&envelope_result.nonce),
        encrypted_key: B64.encode(&envelope_result.encrypted_key),
        filename: req.filename.clone(),
        mime_type: req.mime_type.clone(),
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
            // 持久化链到磁盘（异步写入）
            let save_path = state.chain_file.clone();
            let chain_clone = chain.clone();
            let _ = tokio::spawn(async move {
                if let Err(e) = tokio::fs::create_dir_all(
                    save_path.parent().unwrap_or(std::path::Path::new(".")),
                )
                .await
                {
                    eprintln!("保存链失败 (创建目录): {}", e);
                    return;
                }
                match serde_json::to_string_pretty(&chain_clone) {
                    Ok(s) => {
                        if let Err(e) = tokio::fs::write(&save_path, s).await {
                            eprintln!("保存链失败: {}", e);
                        }
                    }
                    Err(e) => eprintln!("序列化链失败: {}", e),
                }
            });
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

    // 校验 admin 签名参数是否存在
    let admin_sig_b64 = match req.admin_signature {
        Some(s) => s,
        None => return internal_error("缺少 admin_signature，拒绝操作").into_response(),
    };
    let admin_pub_b64 = match req.admin_public_key {
        Some(p) => p,
        None => return internal_error("缺少 admin_public_key，拒绝操作").into_response(),
    };

    let mut chain = state.chain.write().await;
    let original_hash = chain
        .blocks
        .get(req.block_index)
        .map(|b| b.hash.clone())
        .unwrap_or_default();

    // 先重建要签名的内容字节（与前端 prepare 保持一致）
    let new_content = match chain.redaction_content_bytes(req.block_index, &label) {
        Ok(c) => c,
        Err(e) => return internal_error(e).into_response(),
    };

    // 验证 admin 的 FAEST 签名（admin_pub_b64 + admin_sig_b64）
    let admin_pub = match base64::engine::general_purpose::STANDARD.decode(&admin_pub_b64) {
        Ok(b) => b,
        Err(e) => {
            return internal_error(format!("admin_public_key Base64 解码失败: {}", e))
                .into_response()
        }
    };
    let admin_sig = match base64::engine::general_purpose::STANDARD.decode(&admin_sig_b64) {
        Ok(b) => b,
        Err(e) => {
            return internal_error(format!("admin_signature Base64 解码失败: {}", e))
                .into_response()
        }
    };

    let signer = FaestImpl;
    match signer.verify(&new_content, &admin_sig, &admin_pub) {
        Ok(true) => { /* 通过，继续 */ }
        Ok(false) => return internal_error("管理员签名验证失败，拒绝修订").into_response(),
        Err(e) => return internal_error(format!("管理员签名验证错误: {}", e)).into_response(),
    }

    // 验证通过后执行 redact
    match chain.redact_block(req.block_index, &state.ch, &label) {
        Ok(_) => {
            let updated_block = chain.blocks.get(req.block_index).cloned();
            // 持久化链到磁盘（异步写入）
            let save_path = state.chain_file.clone();
            let chain_clone = chain.clone();
            let _ = tokio::spawn(async move {
                if let Err(e) = tokio::fs::create_dir_all(
                    save_path.parent().unwrap_or(std::path::Path::new(".")),
                )
                .await
                {
                    eprintln!("保存链失败 (创建目录): {}", e);
                    return;
                }
                match serde_json::to_string_pretty(&chain_clone) {
                    Ok(s) => {
                        if let Err(e) = tokio::fs::write(&save_path, s).await {
                            eprintln!("保存链失败: {}", e);
                        }
                    }
                    Err(e) => eprintln!("序列化链失败: {}", e),
                }
            });
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

// POST /redact_prepare — 生成要由 Admin 签名的消息（Base64）
#[derive(Deserialize)]
struct RedactPrepareRequest {
    block_index: usize,
    redaction_label: Option<String>,
}

async fn redact_prepare(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedactPrepareRequest>,
) -> impl IntoResponse {
    let label = req
        .redaction_label
        .unwrap_or_else(|| "【已合规抹除】".to_string());
    let chain = state.chain.read().await;
    match chain.redaction_content_bytes(req.block_index, &label) {
        Ok(content) => Json(serde_json::json!({ "message_base64": base64::engine::general_purpose::STANDARD.encode(&content) })).into_response(),
        Err(e) => internal_error(e).into_response(),
    }
}

// POST /admin_sign — 使用 FAEST 私钥对任意消息签名（演示用；生产不要传私钥）
#[derive(Deserialize)]
struct AdminSignRequest {
    private_key_base64: String,
    message_base64: String,
}

async fn admin_sign(Json(req): Json<AdminSignRequest>) -> impl IntoResponse {
    let priv_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.private_key_base64)
    {
        Ok(b) => b,
        Err(e) => {
            return internal_error(format!("private_key Base64 解码失败: {}", e)).into_response()
        }
    };
    let msg = match base64::engine::general_purpose::STANDARD.decode(&req.message_base64) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("message Base64 解码失败: {}", e)).into_response(),
    };

    let signer = FaestImpl;
    match signer.sign(&msg, &priv_bytes) {
        Ok(sig) => Json(serde_json::json!({ "signature_base64": base64::engine::general_purpose::STANDARD.encode(&sig) })).into_response(),
        Err(e) => internal_error(format!("签名失败: {}", e)).into_response(),
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
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("区块 {} 不存在", index),
                }),
                // 验证链完整性（使用当前 Admin RSA 派生的变色龙哈希参数）
            )
                .into_response()
        }
    };

    // 从 Block 中恢复 EnvelopeResult
    let ciphertext = match B64.decode(&block.tx.payload.ciphertext) {
        Ok(b) => b,
        Err(e) => {
            return internal_error(format!("payload ciphertext 解码失败: {}", e)).into_response()
        }
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
                "filename": block.tx.payload.filename,
                "mime_type": block.tx.payload.mime_type,
                "block_index": index,
            }))
            .into_response()
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
    // 优化：将 Admin 私钥持久化到磁盘，保证重启后仍能解密此前上链的数字信封。
    use std::fs;
    use std::path::Path;
    let admin_pem_path = Path::new("data/admin_rsa.pem");
    println!("🔑 正在加载或生成 Admin RSA-2048 密钥对（用于变色龙哈希陷阱），路径：{}", admin_pem_path.display());

    // 确保 data/ 目录存在
    if let Some(parent) = admin_pem_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            println!("⚠️ 无法创建目录 {}: {}", parent.display(), e);
        }
    }
    let (admin_rsa_priv, admin_rsa_pub) = if admin_pem_path.exists() {
        // 尝试从 PEM 加载私钥
        match fs::read_to_string(admin_pem_path) {
            Ok(pem_str) => match rsa::RsaPrivateKey::from_pkcs1_pem(&pem_str) {
                Ok(privk) => {
                    let pubk = rsa::RsaPublicKey::from(&privk);
                    println!("✅ 成功从 admin_rsa.pem 加载 Admin 私钥");
                    (privk, pubk)
                }
                Err(e) => {
                    println!("⚠️ 从 admin_rsa.pem 解析私钥失败，将重新生成：{}", e);
                    let (p, pubk) = generate_rsa_keypair()?;
                    // 覆写文件
                    if let Ok(pem) = p.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
                        let _ = fs::write(admin_pem_path, pem);
                    }
                    (p, pubk)
                }
            },
            Err(e) => {
                println!("⚠️ 读取 admin_rsa.pem 失败，将重新生成：{}", e);
                let (p, pubk) = generate_rsa_keypair()?;
                if let Ok(pem) = p.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
                    let _ = fs::write(admin_pem_path, pem);
                }
                (p, pubk)
            }
        }
    } else {
        // 文件不存在，生成并写入
        let (p, pubk) = generate_rsa_keypair()?;
        if let Ok(pem) = p.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF) {
            let _ = fs::write(admin_pem_path, pem);
            println!("✅ 新生成 Admin 私钥并写入 admin_rsa.pem");
        }
        (p, pubk)
    };

    let ch = ChameleonHash::setup(&admin_rsa_priv);

    // 初始化区块链并生成创世块（使用 FAEST 密钥作为创世签名示例）
    println!("⛓  正在初始化区块链并生成创世块...");
    // 尝试从磁盘加载已存在的链（位于 data/chain.json），若不存在则生成创世块并持久化。
    let chain_path = Path::new("data/chain.json").to_path_buf();
    let blockchain: Blockchain = if chain_path.exists() {
        match Blockchain::load_from_path(&chain_path) {
            Ok(bc) => {
                println!(
                    "✅ 已从 {} 加载区块链，长度: {}",
                    chain_path.display(),
                    bc.blocks.len()
                );
                bc
            }
            Err(e) => {
                println!("⚠️ 载入区块链失败，改为生成新链: {}", e);
                let (genesis_priv, genesis_pub) = generate_faest_keypair();
                let mut bc = Blockchain::new();
                bc.genesis_block(&ch, &admin_rsa_pub, &genesis_priv, &genesis_pub)?;
                // 尝试保存
                if let Err(e) = bc.save_to_path(&chain_path) {
                    println!("⚠️ 保存新链到磁盘失败: {}", e);
                }
                bc
            }
        }
    } else {
        let (genesis_priv, genesis_pub) = generate_faest_keypair();
        let mut bc = Blockchain::new();
        bc.genesis_block(&ch, &admin_rsa_pub, &genesis_priv, &genesis_pub)?;
        // 保存初始链到磁盘
        if let Err(e) = bc.save_to_path(&chain_path) {
            println!("⚠️ 保存创世链到磁盘失败: {}", e);
        }
        println!("✅ 创世块已生成并持久化，链长度: {}", bc.blocks.len());
        bc
    };

    let state = Arc::new(AppState {
        ch,
        chain: RwLock::new(blockchain),
        admin_rsa_pub,
        admin_rsa_priv: admin_rsa_priv,
        chain_file: chain_path,
    });

    // 配置路由
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/health", get(|| async { (StatusCode::OK, Json(serde_json::json!({"ok": true}))) }))
        .route("/keys", get(get_keys))
        .route("/faest_keys", get(get_faest_keys))
        .route("/chain", get(get_chain))
        .route("/redact_prepare", post(redact_prepare))
        .route("/admin_sign", post(admin_sign))
        .route("/block_plain/:index", get(get_block_plain))
        .route("/encrypt_and_mine", post(encrypt_and_mine))
        .route("/redact", post(redact_block))
        .nest_service("/static", ServeDir::new("static"))
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
