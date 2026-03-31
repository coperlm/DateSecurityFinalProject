use crate::chain::{EncryptedPayload, Transaction};
use crate::crypto::{envelope_decrypt, envelope_encrypt, generate_faest_keypair, generate_rsa_keypair, EnvelopeResult, FaestImpl, PqSignature};
use crate::faest_ffi;
use crate::progress;
use crate::state::{AppState, new_uuid};
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use chrono::Utc;
use tokio::time::timeout;
use std::time::Duration;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};

static LAST_ERRORS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn record_error(err: String) {
    let mut store = LAST_ERRORS.lock().unwrap();
    store.push(err);
    while store.len() > 50 { store.remove(0); }
}

fn trace(msg: &str) {
    println!("[{}] {}", Utc::now().to_rfc3339(), msg);
}

#[derive(Deserialize, Clone)]
pub struct EncryptAndMineRequest {
    pub plaintext: String,
    pub plaintext_base64: Option<bool>,
    pub sender_private_key: String,
    pub sender_public_key: String,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct RedactRequest {
    pub block_index: usize,
    pub redaction_label: Option<String>,
    pub admin_public_key: Option<String>,
    pub admin_signature: Option<String>,
}

#[derive(Serialize)]
pub struct KeysResponse {
    pub faest_private_key: String,
    pub faest_public_key: String,
    pub rsa_public_key_pem: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn internal_error(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: e.to_string(),
        }),
    )
}

pub async fn get_keys() -> impl IntoResponse {
    let (fa_priv, fa_pub) = generate_faest_keypair();
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

pub async fn get_faest_keys() -> impl IntoResponse {
    match faest_ffi::keygen() {
        Ok((pk, sk)) => Json(serde_json::json!({
            "faest_public_key": B64.encode(&pk),
            "faest_private_key": B64.encode(&sk),
        }))
        .into_response(),
        Err(e) => internal_error(format!("FAEST keygen failed: {}", e)).into_response(),
    }
}

pub async fn get_chain(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let chain = state.chain.read().await;
    let is_valid = chain.verify_chain(&state.ch);
    Json(serde_json::json!({
        "blocks": chain.blocks,
        "is_valid": is_valid,
        "length": chain.blocks.len()
    }))
    .into_response()
}

pub async fn get_block_plain(
    State(state): State<std::sync::Arc<AppState>>,
    Path(index): Path<usize>,
) -> impl IntoResponse {
    let chain = state.chain.read().await;
    let block = chain.blocks.get(index);
    if block.is_none() {
        return (StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("区块 {} 不存在", index) })).into_response();
    }
    let block = block.unwrap().clone();

    // 处理变色龙合规修订之后的红acted 区块，避免解密失败
    if block.tx.payload.encrypted_key == "UkVEQUNURUQ=" {
        let redacted_plain = match B64.decode(&block.tx.payload.ciphertext) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => "【已合规抹除】".to_string(),
        };
        return Json(serde_json::json!({
            "success": true,
            "redacted": true,
            "plaintext_base64": B64.encode(redacted_plain.as_bytes()),
            "plaintext_utf8": redacted_plain,
            "filename": block.tx.payload.filename,
            "mime_type": block.tx.payload.mime_type,
            "block_index": index,
        })).into_response();
    }

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

    let envelope = EnvelopeResult { ciphertext, nonce, encrypted_key };
    match envelope_decrypt(&envelope, &state.admin_rsa_priv) {
        Ok(plain_bytes) => {
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

pub async fn get_progress(Path(id): Path<String>) -> impl IntoResponse {
    match progress::get_progress(&id) {
        Some(p) => Json(serde_json::json!({"ok": true, "progress": p})).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"ok": false, "error": "op_id not found"}))).into_response(),
    }
}

pub async fn faest_admin_exists() -> impl IntoResponse {
    let pubp = std::path::Path::new("data/admin_faest_pub.b64");
    let privp = std::path::Path::new("data/admin_faest_priv.b64");
    Json(serde_json::json!({"exists": pubp.exists() && privp.exists()})).into_response()
}

pub async fn get_faest_admin_keys() -> impl IntoResponse {
    let pubp = std::path::Path::new("data/admin_faest_pub.b64");
    let privp = std::path::Path::new("data/admin_faest_priv.b64");
    if !pubp.exists() || !privp.exists() {
        return (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Admin FAEST keys not found".to_string() })).into_response();
    }
    match (std::fs::read_to_string(privp), std::fs::read_to_string(pubp)) {
        (Ok(privs), Ok(pubs)) => Json(serde_json::json!({"faest_private_key": privs.trim(), "faest_public_key": pubs.trim()})).into_response(),
        (Err(e), _) | (_, Err(e)) => internal_error(format!("读取 Admin FAEST 密钥失败: {}", e)).into_response(),
    }
}

pub async fn post_faest_admin_keys() -> impl IntoResponse {
    let pubp = std::path::Path::new("data/admin_faest_pub.b64");
    let privp = std::path::Path::new("data/admin_faest_priv.b64");
    if pubp.exists() || privp.exists() {
        return (StatusCode::CONFLICT, Json(ErrorResponse { error: "Admin FAEST keys already exist on server".to_string() })).into_response();
    }
    match timeout(Duration::from_secs(30), tokio::task::spawn_blocking(|| crate::faest_ffi::keygen())).await {
        Ok(Ok(Ok((pk, sk)))) => {
            if let Err(e) = std::fs::create_dir_all("data") { return internal_error(format!("无法创建 data 目录: {}", e)).into_response(); }
            let sk_b64 = B64.encode(&sk);
            let pk_b64 = B64.encode(&pk);
            if let Err(e) = std::fs::write(privp, &sk_b64) { return internal_error(format!("写入私钥失败: {}", e)).into_response(); }
            if let Err(e) = std::fs::write(pubp, &pk_b64) { return internal_error(format!("写入公钥失败: {}", e)).into_response(); }
            Json(serde_json::json!({"faest_private_key": sk_b64, "faest_public_key": pk_b64})).into_response()
        }
        Ok(Ok(Err(e))) => internal_error(format!("FAEST keygen failed: {}", e)).into_response(),
        Ok(Err(join_err)) => internal_error(format!("FAEST keygen join error: {}", join_err)).into_response(),
        Err(_) => internal_error("FAEST keygen timed out").into_response(),
    }
}

pub async fn get_admin_rsa(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let n_str = state.admin_rsa_pub.n().to_str_radix(10);
    let e_str = state.admin_rsa_pub.e().to_str_radix(10);
    let d_str = state.admin_rsa_priv.d().to_str_radix(10);
    let d_masked = if d_str.len() <= 24 {
        d_str.clone()
    } else {
        format!("{}...{}", &d_str[..6], &d_str[d_str.len()-6..])
    };
    Json(serde_json::json!({"ok": true, "n": n_str, "e": e_str, "d_masked": d_masked})).into_response()
}

pub async fn debug_last_errors() -> impl IntoResponse {
    let store = LAST_ERRORS.lock().unwrap();
    Json(serde_json::json!({"last_errors": store.clone()})).into_response()
}

pub async fn get_chain_and_mine(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<EncryptAndMineRequest>,
) -> impl IntoResponse {
    let op_id = new_uuid();
    progress::create_progress(op_id.clone(), &["envelope_encrypt", "faest_sign", "ch_compute", "persist_chain"]);

    let op_id_for_task = op_id.clone();
    let state_cloned = state.clone();
    let req_cloned = req.clone();

    tokio::spawn(async move {
        let op_id = op_id_for_task;
        trace(&format!("encrypt_and_mine op={} 新请求开始", op_id));
        progress::update_progress_step(&op_id, "envelope_encrypt", "in_progress", None);

        let sender_priv = match B64.decode(&req_cloned.sender_private_key) {
            Ok(b) => b,
            Err(e) => {
                progress::update_progress_step(&op_id, "envelope_encrypt", "failed", Some(format!("私钥 Base64 解码失败: {}", e)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };
        let sender_pub = match B64.decode(&req_cloned.sender_public_key) {
            Ok(b) => b,
            Err(e) => {
                progress::update_progress_step(&op_id, "envelope_encrypt", "failed", Some(format!("公钥 Base64 解码失败: {}", e)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };

        let plaintext_bytes = if req_cloned.plaintext_base64.unwrap_or(false) {
            match B64.decode(&req_cloned.plaintext) {
                Ok(b) => b,
                Err(e) => {
                    progress::update_progress_step(&op_id, "envelope_encrypt", "failed", Some(format!("plaintext Base64 解码失败: {}", e)));
                    progress::set_progress_done(&op_id, false, None);
                    return;
                }
            }
        } else {
            req_cloned.plaintext.as_bytes().to_vec()
        };

        let envelope_result = match envelope_encrypt(&plaintext_bytes, &state_cloned.admin_rsa_pub) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("envelope encrypt failed: {}", e);
                trace(&format!("encrypt_and_mine op={} error {}", op_id, msg));
                record_error(format!("op={} envelope_encrypt error: {}", op_id, msg));
                progress::update_progress_step(&op_id, "envelope_encrypt", "failed", Some(msg));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };
        trace(&format!("encrypt_and_mine op={} envelope_encrypt done", op_id));
        progress::update_progress_step(&op_id, "envelope_encrypt", "done", None);

        // 继续 faest_sign
        progress::update_progress_step(&op_id, "faest_sign", "in_progress", None);
        let payload = EncryptedPayload {
            ciphertext: B64.encode(&envelope_result.ciphertext),
            nonce: B64.encode(&envelope_result.nonce),
            encrypted_key: B64.encode(&envelope_result.encrypted_key),
            filename: req_cloned.filename.clone(),
            mime_type: req_cloned.mime_type.clone(),
        };
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                progress::update_progress_step(&op_id, "faest_sign", "failed", Some(format!("serialize payload failed: {}", e)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };

        let sign_res = tokio::task::spawn_blocking(move || {
            PqSignature::sign(&FaestImpl, &payload_bytes, &sender_priv)
        })
        .await;

        let sig = match sign_res {
            Ok(Ok(s)) => {
                trace(&format!("encrypt_and_mine op={} faest_sign done", op_id));
                s
            }
            Ok(Err(e)) => {
                let msg = format!("FAEST sign failed: {}", e);
                trace(&format!("encrypt_and_mine op={} error {}", op_id, msg));
                record_error(format!("op={} faest_sign error: {}", op_id, msg));
                progress::update_progress_step(&op_id, "faest_sign", "failed", Some(msg));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
            Err(join_err) => {
                let msg = format!("FAEST sign join error: {}", join_err);
                trace(&format!("encrypt_and_mine op={} error {}", op_id, msg));
                record_error(format!("op={} faest_sign error: {}", op_id, msg));
                progress::update_progress_step(&op_id, "faest_sign", "failed", Some(msg));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };
        progress::update_progress_step(&op_id, "faest_sign", "done", None);

        let tx = Transaction {
            tx_id: new_uuid(),
            payload,
            sender_signature: B64.encode(&sig),
            sender_pub_key: B64.encode(&sender_pub),
        };

        // ch_compute
        progress::update_progress_step(&op_id, "ch_compute", "in_progress", None);
        let mut chain = state_cloned.chain.write().await;
        match chain.add_block(&state_cloned.ch, tx) {
            Ok(()) => {
                trace(&format!("encrypt_and_mine op={} ch_compute done", op_id));
                progress::update_progress_step(&op_id, "ch_compute", "done", None);
            }
            Err(e) => {
                let msg = format!("add_block failed: {}", e);
                trace(&format!("encrypt_and_mine op={} error {}", op_id, msg));
                record_error(format!("op={} ch_compute error: {}", op_id, msg));
                progress::update_progress_step(&op_id, "ch_compute", "failed", Some(msg));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        }

        // persist_chain
        progress::update_progress_step(&op_id, "persist_chain", "in_progress", None);
        let chain_clone = chain.clone();
        let save_path = state_cloned.chain_file.clone();

        let persist = tokio::spawn(async move {
            tokio::fs::create_dir_all(save_path.parent().unwrap_or(std::path::Path::new("."))).await?;
            let text = serde_json::to_string_pretty(&chain_clone)?;
            tokio::fs::write(save_path, text).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match persist {
            Ok(Ok(())) => {
                progress::update_progress_step(&op_id, "persist_chain", "done", None);
                progress::set_progress_done(&op_id, true, Some(serde_json::json!({
                    "message": "交易已成功打包上链",
                    "block": chain.blocks.last()
                })));
            }
            Ok(Err(e)) => {
                progress::update_progress_step(&op_id, "persist_chain", "failed", Some(format!("persist error: {}", e)));
                progress::set_progress_done(&op_id, false, None);
            }
            Err(join_err) => {
                progress::update_progress_step(&op_id, "persist_chain", "failed", Some(format!("persist task join error: {}", join_err)));
                progress::set_progress_done(&op_id, false, None);
            }
        }
    });

    Json(serde_json::json!({"ok": true, "op_id": op_id})).into_response()
}

pub async fn redact_block(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<RedactRequest>,
) -> impl IntoResponse {
    let op_id = new_uuid();
    progress::create_progress(op_id.clone(), &["prepare", "verify_signature", "apply_redact", "persist_chain"]);

    let op_id_for_task = op_id.clone();
    let state_cloned = state.clone();
    let req_cloned = req.clone();

    tokio::spawn(async move {
        let op_id = op_id_for_task;
        trace(&format!("redact op={} start", op_id));
        progress::update_progress_step(&op_id, "prepare", "in_progress", None);

        let label = req_cloned.redaction_label.unwrap_or_else(|| "【已合规抹除】".to_string());
        let new_content = match state_cloned.chain.read().await.redaction_content_bytes(req_cloned.block_index, &label) {
            Ok(c) => c,
            Err(e) => {
                progress::update_progress_step(&op_id, "prepare", "failed", Some(format!("redaction content error: {}", e)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };
        progress::update_progress_step(&op_id, "prepare", "done", None);

        progress::update_progress_step(&op_id, "verify_signature", "in_progress", None);
        let admin_pub = match req_cloned.admin_public_key {
            Some(p) => match B64.decode(&p) {
                Ok(b) => b,
                Err(e) => {
                    progress::update_progress_step(&op_id, "verify_signature", "failed", Some(format!("admin_public_key Base64 解码失败: {}", e)));
                    progress::set_progress_done(&op_id, false, None);
                    return;
                }
            },
            None => {
                progress::update_progress_step(&op_id, "verify_signature", "failed", Some("缺少 admin_public_key".to_string()));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };
        let admin_sig = match req_cloned.admin_signature {
            Some(s) => match B64.decode(&s) {
                Ok(b) => b,
                Err(e) => {
                    progress::update_progress_step(&op_id, "verify_signature", "failed", Some(format!("admin_signature Base64 解码失败: {}", e)));
                    progress::set_progress_done(&op_id, false, None);
                    return;
                }
            },
            None => {
                progress::update_progress_step(&op_id, "verify_signature", "failed", Some("缺少 admin_signature".to_string()));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        };

        let verify_res = tokio::task::spawn_blocking(move || {
            let signer = FaestImpl;
            signer.verify(&new_content, &admin_sig, &admin_pub)
        })
        .await;

        match verify_res {
            Ok(Ok(true)) => progress::update_progress_step(&op_id, "verify_signature", "done", None),
            Ok(Ok(false)) => {
                progress::update_progress_step(&op_id, "verify_signature", "failed", Some("管理员签名验证失败".to_string()));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
            Ok(Err(e)) => {
                progress::update_progress_step(&op_id, "verify_signature", "failed", Some(format!("验证错误: {}", e)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
            Err(join_err) => {
                progress::update_progress_step(&op_id, "verify_signature", "failed", Some(format!("签名验证 join 错误: {}", join_err)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        }

        progress::update_progress_step(&op_id, "apply_redact", "in_progress", None);
        {
            let mut chain = state_cloned.chain.write().await;
            if let Err(e) = chain.redact_block(req_cloned.block_index, &state_cloned.ch, &label) {
                progress::update_progress_step(&op_id, "apply_redact", "failed", Some(format!("redact_block failed: {}", e)));
                progress::set_progress_done(&op_id, false, None);
                return;
            }
        }
        progress::update_progress_step(&op_id, "apply_redact", "done", None);

        progress::update_progress_step(&op_id, "persist_chain", "in_progress", None);
        let state_clone_2 = state_cloned.clone();
        let persist_result = tokio::spawn(async move {
            let chain = state_clone_2.chain.read().await;
            tokio::fs::create_dir_all(state_clone_2.chain_file.parent().unwrap_or(std::path::Path::new("."))).await?;
            let text = serde_json::to_string_pretty(&*chain)?;
            tokio::fs::write(&state_clone_2.chain_file, text).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match persist_result {
            Ok(Ok(())) => {
                progress::update_progress_step(&op_id, "persist_chain", "done", None);
                let chain_reader = state_cloned.chain.read().await;
                let block = chain_reader.blocks.get(req_cloned.block_index).cloned();
                progress::set_progress_done(&op_id, true, Some(serde_json::json!({
                    "message": format!("区块 {} 已合规修订", req_cloned.block_index),
                    "block": block,
                })));
            }
            Ok(Err(e)) => {
                progress::update_progress_step(&op_id, "persist_chain", "failed", Some(format!("persist error: {}", e)));
                progress::set_progress_done(&op_id, false, None);
            }
            Err(join_err) => {
                progress::update_progress_step(&op_id, "persist_chain", "failed", Some(format!("persist task join error: {}", join_err)));
                progress::set_progress_done(&op_id, false, None);
            }
        }
    });

    Json(serde_json::json!({"ok": true, "op_id": op_id})).into_response()
}

#[derive(Deserialize, Clone)]
pub struct RedactPrepareRequest {
    pub block_index: usize,
    pub redaction_label: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct AdminSignRequest {
    pub private_key_base64: String,
    pub message_base64: String,
}

pub async fn redact_prepare(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<RedactPrepareRequest>,
) -> impl IntoResponse {
    let label = req.redaction_label.unwrap_or_else(|| "【已合规抹除】".to_string());
    let chain = state.chain.read().await;
    match chain.redaction_content_bytes(req.block_index, &label) {
        Ok(content) => Json(serde_json::json!({ "message_base64": B64.encode(&content) })).into_response(),
        Err(e) => internal_error(e).into_response(),
    }
}

pub async fn admin_sign(Json(req): Json<AdminSignRequest>) -> impl IntoResponse {
    let priv_bytes = match B64.decode(&req.private_key_base64) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("private_key Base64 解码失败: {}", e)).into_response(),
    };
    let msg = match B64.decode(&req.message_base64) {
        Ok(b) => b,
        Err(e) => return internal_error(format!("message Base64 解码失败: {}", e)).into_response(),
    };

    match FaestImpl.sign(&msg, &priv_bytes) {
        Ok(sig) => Json(serde_json::json!({ "signature_base64": B64.encode(&sig) })).into_response(),
        Err(e) => internal_error(format!("签名失败: {}", e)).into_response(),
    }
}
