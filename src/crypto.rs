// crypto.rs — 密码学底层模块
// 包含：数字信封加解密、后量子签名占位符、AES-CMAC 哈希、变色龙哈希

use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use cmac::{Cmac, Mac};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15::Pkcs1v15Encrypt,
    RsaPrivateKey, RsaPublicKey,
};

// ────────────────────────────────────────────────────────────────────────────
// § 1  后量子签名 Trait（Ed25519 占位实现）
// ────────────────────────────────────────────────────────────────────────────

/// 后量子签名算法的统一抽象接口。
/// 此处未来将通过 C-FFI 接入 FAEST 后量子签名算法。
pub trait PqSignature {
    /// 对消息 `message` 进行签名，返回签名字节。
    fn sign(&self, message: &[u8], private_key: &[u8]) -> Result<Vec<u8>>;

    /// 验证签名。`true` 表示合法。
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool>;
}

/// Ed25519 签名实现——作为 FAEST 后量子签名的临时占位符。
pub struct Ed25519Impl;

impl PqSignature for Ed25519Impl {
    fn sign(&self, message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        // 从 32 字节种子还原 SigningKey
        let key_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow!("Ed25519 私钥必须为 32 字节"))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let sig: Signature = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow!("Ed25519 公钥必须为 32 字节"))?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow!("Ed25519 签名必须为 64 字节"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow!("无效的 Ed25519 公钥: {}", e))?;
        let sig = Signature::from_bytes(&sig_bytes);
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

/// 生成一对 Ed25519 密钥（签名私钥 + 验证公钥），均以 32 字节表示。
pub fn generate_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// § 2  数字信封加密 / 解密
// ────────────────────────────────────────────────────────────────────────────

/// 数字信封加密结果（可直接序列化为 JSON）。
#[derive(Debug, Clone)]
pub struct EnvelopeResult {
    /// AES-GCM 密文（含 GCM 认证 Tag）
    pub ciphertext: Vec<u8>,
    /// AES-GCM Nonce（12 字节）
    pub nonce: Vec<u8>,
    /// RSA-PKCS1v15 加密后的 AES-256 密钥
    pub encrypted_key: Vec<u8>,
}

/// 数字信封加密：
/// 1. 随机生成 AES-256 密钥 K；
/// 2. 使用 AES-256-GCM 加密明文 M → 密文 C；
/// 3. 使用接收者 RSA 公钥加密 K → E_K；
/// 产物：(C, Nonce, E_K)
pub fn envelope_encrypt(plaintext: &[u8], rsa_pub_key: &RsaPublicKey) -> Result<EnvelopeResult> {
    // 随机生成 AES-256 密钥（32 字节）
    let aes_key = Aes256Gcm::generate_key(&mut AeadOsRng);

    // AES-GCM 加密
    let cipher = Aes256Gcm::new(&aes_key);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AES-GCM 加密失败: {}", e))?;

    // RSA-PKCS1v15 加密 AES 密钥
    let mut rng = OsRng;
    let encrypted_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, aes_key.as_slice())
        .map_err(|e| anyhow!("RSA 加密 AES 密钥失败: {}", e))?;

    Ok(EnvelopeResult {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        encrypted_key,
    })
}

/// 数字信封解密：
/// 1. 使用 RSA 私钥解密 E_K → K；
/// 2. 使用 K 解密密文 C → 明文 M。
pub fn envelope_decrypt(
    envelope: &EnvelopeResult,
    rsa_priv_key: &RsaPrivateKey,
) -> Result<Vec<u8>> {
    // 解密 AES 密钥
    let aes_key_bytes = rsa_priv_key
        .decrypt(Pkcs1v15Encrypt, &envelope.encrypted_key)
        .map_err(|e| anyhow!("RSA 解密 AES 密钥失败: {}", e))?;

    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|e| anyhow!("AES-GCM 解密失败: {}", e))?;

    Ok(plaintext)
}

/// 生成 RSA 密钥对（2048 位）。
pub fn generate_rsa_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key))
}

// ────────────────────────────────────────────────────────────────────────────
// § 3  基于 AES-128-CMAC 的哈希函数 H_AES(m)
// ────────────────────────────────────────────────────────────────────────────

/// 使用固定 zero-key 的 AES-128-CMAC 将任意字节压缩为 128-bit BigUint。
/// H_AES(m) 的结果用于变色龙哈希计算。
///
/// 注意：固定 key 使其行为类似于一个公共压缩函数，
/// 而非 MAC（MAC 需要秘密 key）。此处仅用于哈希语义。
pub fn h_aes(data: &[u8]) -> BigUint {
    // 使用全零 128-bit key（公共常量，非密钥用途）
    let key = [0u8; 16];
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(&key).expect("AES-CMAC 初始化失败");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    BigUint::from_bytes_be(&tag)
}

// ────────────────────────────────────────────────────────────────────────────
// § 4  变色龙哈希（Chameleon Hash，基于 RSA 陷门）
// ────────────────────────────────────────────────────────────────────────────

/// 变色龙哈希系统的参数（Admin 超级管理员持有）。
#[derive(Debug, Clone)]
pub struct ChameleonHash {
    /// RSA 模数 N
    pub n: BigUint,
    /// RSA 公钥指数 e
    pub e: BigUint,
    /// RSA 私钥指数 d（陷门，仅 Admin 持有）
    pub d: BigUint,
}

impl ChameleonHash {
    /// 从 RSA 密钥对初始化变色龙哈希参数。
    pub fn setup(priv_key: &RsaPrivateKey) -> Self {
        use rsa::traits::PrivateKeyParts;
        use rsa::traits::PublicKeyParts;

        let pub_key = RsaPublicKey::from(priv_key);
        let n = BigUint::from_bytes_be(&pub_key.n().to_bytes_be());
        let e = BigUint::from_bytes_be(&pub_key.e().to_bytes_be());
        let d = BigUint::from_bytes_be(&priv_key.d().to_bytes_be());

        ChameleonHash { n, e, d }
    }

    /// 正向哈希（矿工打包）：
    /// CH = H_AES(m) * r^e mod N
    pub fn hash(&self, data: &[u8], r: &BigUint) -> BigUint {
        let hm = h_aes(data);
        let re = r.modpow(&self.e, &self.n);
        (hm * re) % &self.n
    }

    /// 生成合法的随机数 r（r ∈ Z_N*，即 gcd(r, N) == 1）。
    pub fn random_r(&self) -> BigUint {
        let mut rng = rand::thread_rng();
        loop {
            let r = rng.gen_biguint_below(&self.n);
            if !r.is_zero() && r.gcd(&self.n).is_one() {
                return r;
            }
        }
    }

    /// 陷门碰撞（合规修订）：
    /// 给定旧数据 m、旧随机数 r 和新数据 m'，Admin 利用陷门 d 计算 r'，
    /// 使得 CH(m, r) == CH(m', r')。
    ///
    /// 公式：r' = (H_AES(m) * H_AES(m')^{-1})^d * r mod N
    pub fn forge(&self, old_data: &[u8], old_r: &BigUint, new_data: &[u8]) -> Result<BigUint> {
        let hm = h_aes(old_data);
        let hm_new = h_aes(new_data);

        // 计算 H_AES(m') 在模 N 下的逆元
        let hm_new_inv = mod_inverse(&hm_new, &self.n)
            .ok_or_else(|| anyhow!("H_AES(m') 与 N 不互质，无法计算逆元"))?;

        // ratio = H_AES(m) * H_AES(m')^{-1} mod N
        let ratio = (hm * hm_new_inv) % &self.n;

        // ratio_d = ratio^d mod N
        let ratio_d = ratio.modpow(&self.d, &self.n);

        // r' = ratio_d * r mod N
        let r_prime = (ratio_d * old_r) % &self.n;

        Ok(r_prime)
    }
}

/// 扩展欧几里得算法：计算 a 在模 m 下的逆元。
/// 返回 None 表示不互质（逆元不存在）。
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;

    if a.is_zero() {
        return None;
    }

    // 转换为有符号大整数进行扩展 GCD
    let a_int = BigInt::from(a.clone());
    let m_int = BigInt::from(m.clone());

    let (g, x, _) = extended_gcd(a_int, m_int.clone());
    if g != BigInt::one() {
        return None; // 不互质
    }

    // 将结果规范化到 [0, m)
    let result = ((x % &m_int) + &m_int) % &m_int;
    result.to_biguint()
}

/// 扩展欧几里得算法，返回 (gcd, x, y) 使得 a*x + b*y = gcd。
fn extended_gcd(a: num_bigint::BigInt, b: num_bigint::BigInt) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
    use num_bigint::BigInt;

    if a.is_zero() {
        return (b, BigInt::zero(), BigInt::one());
    }
    let (g, x, y) = extended_gcd(b.clone() % &a, a.clone());
    (g, y - (b / &a) * &x, x)
}

// ────────────────────────────────────────────────────────────────────────────
// § 5  单元测试
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试数字信封加解密的完整往返。
    #[test]
    fn test_envelope_encrypt_decrypt_roundtrip() {
        let (priv_key, pub_key) = generate_rsa_keypair().expect("RSA 密钥生成失败");
        let plaintext = b"Hello, Enterprise Encryption!";

        let envelope = envelope_encrypt(plaintext, &pub_key).expect("加密失败");
        let recovered = envelope_decrypt(&envelope, &priv_key).expect("解密失败");

        assert_eq!(plaintext.as_ref(), recovered.as_slice(), "明文应完整还原");
    }

    /// 测试 Ed25519 签名与验证。
    #[test]
    fn test_ed25519_sign_verify() {
        let (priv_bytes, pub_bytes) = generate_ed25519_keypair();
        let signer = Ed25519Impl;
        let message = b"transaction payload hash";

        let sig = signer.sign(message, &priv_bytes).expect("签名失败");
        let valid = signer
            .verify(message, &sig, &pub_bytes)
            .expect("验证调用失败");
        assert!(valid, "合法签名应验证通过");

        // 篡改消息后应验证失败
        let tampered = b"tampered payload hash!!";
        let invalid = signer
            .verify(tampered, &sig, &pub_bytes)
            .expect("验证调用失败");
        assert!(!invalid, "篡改后签名应验证失败");
    }

    /// 测试变色龙哈希碰撞：hash(m, r) == hash(m', r')。
    #[test]
    fn test_chameleon_hash_collision() {
        let (priv_key, _) = generate_rsa_keypair().expect("RSA 密钥生成失败");
        let ch = ChameleonHash::setup(&priv_key);

        let m = b"original block data";
        let m_prime = b"[REDACTED BY COMPLIANCE]";

        let r = ch.random_r();
        let original_hash = ch.hash(m, &r);

        let r_prime = ch.forge(m, &r, m_prime).expect("碰撞计算失败");
        let forged_hash = ch.hash(m_prime, &r_prime);

        assert_eq!(
            original_hash, forged_hash,
            "变色龙哈希碰撞：两个哈希值必须相等"
        );
    }

    /// 测试 AES-CMAC 哈希的确定性。
    #[test]
    fn test_h_aes_deterministic() {
        let data = b"deterministic input";
        let h1 = h_aes(data);
        let h2 = h_aes(data);
        assert_eq!(h1, h2, "相同输入应产生相同哈希");

        let h3 = h_aes(b"different input");
        assert_ne!(h1, h3, "不同输入应产生不同哈希");
    }
}
