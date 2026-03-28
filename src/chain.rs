// chain.rs — 区块链数据结构与核心逻辑
// 包含：EncryptedPayload、Transaction、Block、Blockchain

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::{ChameleonHash, Ed25519Impl, PqSignature, envelope_encrypt};
use rsa::RsaPublicKey;

// ────────────────────────────────────────────────────────────────────────────
// § 1  核心数据结构
// ────────────────────────────────────────────────────────────────────────────

/// 数字信封加密的产物，包含 AES 密文、Nonce 和被 RSA 加密的 AES 密钥。
/// 所有二进制字段均以 Base64 字符串存储，方便 JSON 序列化。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedPayload {
    /// AES-256-GCM 密文（含 GCM 认证 Tag），Base64 编码
    pub ciphertext: String,
    /// AES-GCM Nonce（12 字节），Base64 编码
    pub nonce: String,
    /// RSA-PKCS1v15 加密后的 AES-256 密钥，Base64 编码
    pub encrypted_key: String,
}

/// 区块链上的一笔交易，携带加密 Payload 与发送者的身份签名。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    /// 交易唯一标识符（UUID v4 字符串）
    pub tx_id: String,
    /// 加密后的数据载荷
    pub payload: EncryptedPayload,
    /// 发送者对 Payload 的 Ed25519 签名，Base64 编码（64 字节）
    pub sender_signature: String,
    /// 发送者 Ed25519 公钥，Base64 编码（32 字节）
    pub sender_pub_key: String,
}

/// 区块链上的一个区块。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    /// 区块索引（从 0 开始，0 为创世块）
    pub index: u64,
    /// 区块时间戳（Unix 毫秒）
    pub timestamp: i64,
    /// 该区块携带的交易
    pub tx: Transaction,
    /// 前一个区块的变色龙哈希值（十六进制字符串）
    pub prev_hash: String,
    /// 当前区块变色龙哈希所用随机数 r（十六进制字符串）
    pub randomness: String,
    /// 当前区块的变色龙哈希值 CH（十六进制字符串）
    pub hash: String,
}

/// 整条区块链，维护一个 Block 的有序列表。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Blockchain {
    /// 所有区块（按索引升序排列）
    pub blocks: Vec<Block>,
}

// ────────────────────────────────────────────────────────────────────────────
// § 2  辅助函数
// ────────────────────────────────────────────────────────────────────────────

/// 将 BigUint 转为十六进制字符串（用于区块 hash / randomness 字段）。
fn biguint_to_hex(n: &BigUint) -> String {
    hex::encode(n.to_bytes_be())
}

/// 从十六进制字符串恢复 BigUint。
fn hex_to_biguint(s: &str) -> Result<BigUint> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("十六进制解码失败: {}", e))?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// 生成 UUID v4（简单实现，基于随机字节）。
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

/// 将 EncryptedPayload 序列化为字节（用于签名/哈希的输入）。
fn payload_to_bytes(payload: &EncryptedPayload) -> Vec<u8> {
    serde_json::to_vec(payload).unwrap_or_default()
}

/// 计算区块核心内容的哈希输入字节（不含当前 hash / randomness 字段）。
fn block_content_bytes(index: u64, timestamp: i64, tx: &Transaction, prev_hash: &str) -> Vec<u8> {
    let combined = format!(
        "{}{}{}{}",
        index,
        timestamp,
        serde_json::to_string(tx).unwrap_or_default(),
        prev_hash
    );
    combined.into_bytes()
}

// ────────────────────────────────────────────────────────────────────────────
// § 3  Blockchain 方法
// ────────────────────────────────────────────────────────────────────────────

impl Blockchain {
    /// 创建一条新的空链（不含创世块）。
    pub fn new() -> Self {
        Blockchain { blocks: Vec::new() }
    }

    /// 创建并追加创世块。
    /// 创世块使用占位 Transaction（payload 为空字符串加密结果），prev_hash 为 "0"*64。
    pub fn genesis_block(
        &mut self,
        ch: &ChameleonHash,
        rsa_pub_key: &RsaPublicKey,
        sender_priv_bytes: &[u8],
        sender_pub_bytes: &[u8],
    ) -> Result<()> {
        let genesis_plaintext = b"GENESIS BLOCK - DateSecurityFinalProject";
        let envelope_result = envelope_encrypt(genesis_plaintext, rsa_pub_key)?;

        let payload = EncryptedPayload {
            ciphertext: B64.encode(&envelope_result.ciphertext),
            nonce: B64.encode(&envelope_result.nonce),
            encrypted_key: B64.encode(&envelope_result.encrypted_key),
        };

        // 签名 payload
        let signer = Ed25519Impl;
        let payload_bytes = payload_to_bytes(&payload);
        let sig_bytes = signer.sign(&payload_bytes, sender_priv_bytes)?;

        let tx = Transaction {
            tx_id: new_uuid(),
            payload,
            sender_signature: B64.encode(&sig_bytes),
            sender_pub_key: B64.encode(sender_pub_bytes),
        };

        let prev_hash = "0".repeat(64); // 创世块的 prev_hash
        let timestamp = Utc::now().timestamp_millis();
        let content = block_content_bytes(0, timestamp, &tx, &prev_hash);

        let r = ch.random_r();
        let hash = ch.hash(&content, &r);

        let block = Block {
            index: 0,
            timestamp,
            tx,
            prev_hash,
            randomness: biguint_to_hex(&r),
            hash: biguint_to_hex(&hash),
        };

        self.blocks.push(block);
        Ok(())
    }

    /// 打包新区块上链：
    /// 1. 验证发送者签名；
    /// 2. 计算变色龙哈希；
    /// 3. 追加区块。
    pub fn add_block(
        &mut self,
        ch: &ChameleonHash,
        tx: Transaction,
    ) -> Result<()> {
        // 验证签名
        let signer = Ed25519Impl;
        let payload_bytes = payload_to_bytes(&tx.payload);
        let sig_bytes = B64
            .decode(&tx.sender_signature)
            .map_err(|e| anyhow!("签名 Base64 解码失败: {}", e))?;
        let pub_bytes = B64
            .decode(&tx.sender_pub_key)
            .map_err(|e| anyhow!("公钥 Base64 解码失败: {}", e))?;

        let valid = signer.verify(&payload_bytes, &sig_bytes, &pub_bytes)?;
        if !valid {
            return Err(anyhow!("交易签名验证失败，拒绝上链"));
        }

        // 获取前一个区块的哈希
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let index = self.blocks.len() as u64;
        let timestamp = Utc::now().timestamp_millis();
        let content = block_content_bytes(index, timestamp, &tx, &prev_hash);

        let r = ch.random_r();
        let hash = ch.hash(&content, &r);

        let block = Block {
            index,
            timestamp,
            tx,
            prev_hash,
            randomness: biguint_to_hex(&r),
            hash: biguint_to_hex(&hash),
        };

        self.blocks.push(block);
        Ok(())
    }

    /// 合规修订（Admin 专用）：
    /// 利用变色龙哈希陷门，将指定区块的 Payload 替换为合规抹除标记，
    /// 同时更新随机数 r'，确保该区块的 CH 值保持不变，链的完整性不受影响。
    pub fn redact_block(
        &mut self,
        index: usize,
        ch: &ChameleonHash,
        redaction_label: &str,
    ) -> Result<()> {
        let block = self
            .blocks
            .get(index)
            .ok_or_else(|| anyhow!("区块索引 {} 不存在", index))?
            .clone();

        // 重新计算旧内容字节（用于 forge）
        let old_content = block_content_bytes(
            block.index,
            block.timestamp,
            &block.tx,
            &block.prev_hash,
        );

        let old_r = hex_to_biguint(&block.randomness)?;

        // 构造合规抹除标记的假 Payload
        let redacted_payload = EncryptedPayload {
            ciphertext: B64.encode(redaction_label.as_bytes()),
            nonce: B64.encode(b"000000000000"),
            encrypted_key: B64.encode(b"REDACTED"),
        };

        // 构造合规标记的 Transaction（保留原 tx_id 和 sender 信息）
        let redacted_tx = Transaction {
            tx_id: block.tx.tx_id.clone(),
            payload: redacted_payload,
            sender_signature: block.tx.sender_signature.clone(),
            sender_pub_key: block.tx.sender_pub_key.clone(),
        };

        // 新内容字节（注意 timestamp 和 prev_hash 保持不变，以维持链接关系）
        let new_content = block_content_bytes(
            block.index,
            block.timestamp,
            &redacted_tx,
            &block.prev_hash,
        );

        // 利用陷门计算新随机数 r'，使 CH(new_content, r') == CH(old_content, old_r)
        let r_prime = ch.forge(&old_content, &old_r, &new_content)?;

        // 验证碰撞正确性（安全关键检查，在所有构建模式下执行）
        if ch.hash(&old_content, &old_r) != ch.hash(&new_content, &r_prime) {
            return Err(anyhow!("内部错误：变色龙哈希碰撞验证失败，陷门计算异常"));
        }

        // 更新区块（hash 值不变，randomness 和 tx 被替换）
        let updated_block = Block {
            index: block.index,
            timestamp: block.timestamp,
            tx: redacted_tx,
            prev_hash: block.prev_hash.clone(),
            randomness: biguint_to_hex(&r_prime),
            hash: block.hash.clone(), // 关键：哈希值保持不变！
        };

        self.blocks[index] = updated_block;
        Ok(())
    }

    /// 验证整条链的哈希完整性。
    pub fn verify_chain(&self, ch: &ChameleonHash) -> bool {
        for (i, block) in self.blocks.iter().enumerate() {
            // 验证 prev_hash 链接
            if i > 0 {
                let expected_prev = &self.blocks[i - 1].hash;
                if &block.prev_hash != expected_prev {
                    return false;
                }
            }

            // 验证当前区块的变色龙哈希
            let content = block_content_bytes(
                block.index,
                block.timestamp,
                &block.tx,
                &block.prev_hash,
            );
            let r = match hex_to_biguint(&block.randomness) {
                Ok(r) => r,
                Err(_) => return false,
            };
            let computed_hash = ch.hash(&content, &r);
            let stored_hash = match hex_to_biguint(&block.hash) {
                Ok(h) => h,
                Err(_) => return false,
            };

            if computed_hash != stored_hash {
                return false;
            }
        }
        true
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// § 4  单元测试
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_ed25519_keypair, generate_rsa_keypair};

    fn setup() -> (ChameleonHash, RsaPublicKey, Vec<u8>, Vec<u8>) {
        let (rsa_priv, rsa_pub) = generate_rsa_keypair().unwrap();
        let ch = ChameleonHash::setup(&rsa_priv);
        let (ed_priv, ed_pub) = generate_ed25519_keypair();
        (ch, rsa_pub, ed_priv, ed_pub)
    }

    #[test]
    fn test_genesis_and_add_block() {
        let (ch, rsa_pub, ed_priv, ed_pub) = setup();
        let mut chain = Blockchain::new();

        // 创世块
        chain.genesis_block(&ch, &rsa_pub, &ed_priv, &ed_pub).unwrap();
        assert_eq!(chain.blocks.len(), 1);

        // 添加新区块
        let plaintext = b"sensitive document content";
        let envelope = crate::crypto::envelope_encrypt(plaintext, &rsa_pub).unwrap();
        let payload = EncryptedPayload {
            ciphertext: B64.encode(&envelope.ciphertext),
            nonce: B64.encode(&envelope.nonce),
            encrypted_key: B64.encode(&envelope.encrypted_key),
        };

        let signer = crate::crypto::Ed25519Impl;
        let payload_bytes = payload_to_bytes(&payload);
        let sig = crate::crypto::PqSignature::sign(&signer, &payload_bytes, &ed_priv).unwrap();

        let tx = Transaction {
            tx_id: new_uuid(),
            payload,
            sender_signature: B64.encode(&sig),
            sender_pub_key: B64.encode(&ed_pub),
        };

        chain.add_block(&ch, tx).unwrap();
        assert_eq!(chain.blocks.len(), 2);
        assert!(chain.verify_chain(&ch), "链完整性验证应通过");
    }

    #[test]
    fn test_redact_preserves_hash() {
        let (ch, rsa_pub, ed_priv, ed_pub) = setup();
        let mut chain = Blockchain::new();
        chain.genesis_block(&ch, &rsa_pub, &ed_priv, &ed_pub).unwrap();

        let original_hash = chain.blocks[0].hash.clone();
        chain.redact_block(0, &ch, "【已合规抹除】").unwrap();
        let after_hash = chain.blocks[0].hash.clone();

        assert_eq!(original_hash, after_hash, "修订后区块 hash 必须保持不变");
        assert!(chain.verify_chain(&ch), "修订后链完整性验证应通过");
    }
}
