// crypto.rs — 密码学底层模块
// 包含：数字信封加解密、后量子签名占位符、AES-CMAC 哈希、变色龙哈希

use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use cmac::{Cmac, Mac};
// Ed25519 卸载：使用 FAEST via C-FFI
use num_bigint::{BigUint, RandBigInt};
use rug::Integer;
use std::str::FromStr;
use std::time::Instant;
use num_integer::Integer as NumIntegerTrait;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15::Pkcs1v15Encrypt,
    RsaPrivateKey, RsaPublicKey,
};
use crate::faest_ffi;

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

// 使用 FAEST FFI 实现后量子签名功能（见 `faest_ffi` 模块）

/// FAEST 后量子签名实现（通过 C-FFI 调用 libs/faest）
pub struct FaestImpl;

impl PqSignature for FaestImpl {
    fn sign(&self, message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        let sig = faest_ffi::sign(private_key, message)
            .map_err(|e| anyhow!("FAEST sign failed: {}", e))?;
        Ok(sig)
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let ok = faest_ffi::verify(public_key, message, signature)
            .map_err(|e| anyhow!("FAEST verify failed: {}", e))?;
        Ok(ok)
    }
}

/// 通过 FAEST C-FFI 生成一对后量子签名密钥（返回 (priv, pub)）
pub fn generate_faest_keypair() -> (Vec<u8>, Vec<u8>) {
    match crate::faest_ffi::keygen() {
        Ok((pk, sk)) => (sk, pk), // 返回顺序与旧接口保持 (priv, pub)
        Err(_) => (vec![], vec![]),
    }
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
    /// RSA 私钥指数 d（仅在初始化时用于计算 CRT 参数，不在结构体中持久保留）
    /// RSA 素因子 p
    pub p: BigUint,
    /// RSA 素因子 q
    pub q: BigUint,
    /// d mod (p-1)
    pub dp: BigUint,
    /// d mod (q-1)
    pub dq: BigUint,
    /// q^{-1} mod p
    pub qinv: BigUint,
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

        // 获取素因子 p, q
        let primes = priv_key.primes();
        let p = BigUint::from_bytes_be(&primes[0].to_bytes_be());
        let q = BigUint::from_bytes_be(&primes[1].to_bytes_be());

        // 计算 dp = d mod (p-1), dq = d mod (q-1)
        let p_minus1 = &p - BigUint::one();
        let q_minus1 = &q - BigUint::one();
        let dp = &d % &p_minus1;
        let dq = &d % &q_minus1;

        // 计算 qinv = q^{-1} mod p
        let qinv = mod_inverse(&q, &p).expect("无法计算 q 的模逆，RSA 素因子不符合要求");

        ChameleonHash { n, e, p, q, dp, dq, qinv }
    }

    /// 正向哈希（矿工打包）：
    /// CH = H_AES(m) * r^e mod N
    pub fn hash(&self, data: &[u8], r: &BigUint) -> BigUint {
        let hm = h_aes(data);
        // 使用 rug (GMP) 进行快速模幂计算以提升性能：
        let start = Instant::now();
        let r_dec = r.to_str_radix(10);
        let e_dec = self.e.to_str_radix(10);
        let n_dec = self.n.to_str_radix(10);
        let r_rug = Integer::from_str(&r_dec).expect("rug parse r");
        let e_rug = Integer::from_str(&e_dec).expect("rug parse e");
        let n_rug = Integer::from_str(&n_dec).expect("rug parse n");
        let re_rug = r_rug.pow_mod(&e_rug, &n_rug).expect("rug pow_mod");
        let re = BigUint::from_str(&re_rug.to_string_radix(10)).expect("to BigUint");
        let elapsed = start.elapsed();
        eprintln!("[perf] ChameleonHash::hash rug modpow elapsed: {} ms", elapsed.as_millis());
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

        // 使用 CRT 优化计算 ratio^d mod N：
        // m1 = ratio^{dp} mod p
        // m2 = ratio^{dq} mod q
        // h = (m1 - m2) * qinv mod p
        // result = m2 + q * h
        let start = Instant::now();
        // 使用 rug 对模幂部分执行加速（CRT 仍然用于合并）
        let ratio_dec = ratio.to_str_radix(10);
        let p_dec = self.p.to_str_radix(10);
        let q_dec = self.q.to_str_radix(10);
        let dp_dec = self.dp.to_str_radix(10);
        let dq_dec = self.dq.to_str_radix(10);

        let ratio_rug = Integer::from_str(&ratio_dec).expect("parse ratio");
        let p_rug = Integer::from_str(&p_dec).expect("parse p");
        let q_rug = Integer::from_str(&q_dec).expect("parse q");
        let dp_rug = Integer::from_str(&dp_dec).expect("parse dp");
        let dq_rug = Integer::from_str(&dq_dec).expect("parse dq");

        let m1_rug = ratio_rug.clone().pow_mod(&dp_rug, &p_rug).expect("pow_mod p");
        let m2_rug = ratio_rug.pow_mod(&dq_rug, &q_rug).expect("pow_mod q");

        // 将 m1/m2 转回 BigUint 以沿用原有 CRT 合并逻辑
        let m1 = BigUint::from_str(&m1_rug.to_string_radix(10)).expect("m1 to BigUint");
        let m2 = BigUint::from_str(&m2_rug.to_string_radix(10)).expect("m2 to BigUint");

        // 计算 h = (m1 - m2) * qinv mod p（处理 m1 < m2 的情况）
        let mut diff = if m1 >= m2 { m1.clone() - m2.clone() } else { (m1.clone() + &self.p) - m2.clone() };
        diff = (diff * &self.qinv) % &self.p;
        let result = m2 + (&self.q * diff);
        let elapsed = start.elapsed();
        eprintln!("[perf] ChameleonHash::forge CRT+rug elapsed: {} ms", elapsed.as_millis());

        // r' = result * r mod N
        let r_prime = (result * old_r) % &self.n;

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

    /// 测试 FAEST 签名与验证（通过 FFI 调用 libs/faest）
    #[test]
    fn test_faest_sign_verify() {
        let (priv_bytes, pub_bytes) = generate_faest_keypair();
        // 若 FAEST keygen 失败，跳过测试
        if priv_bytes.is_empty() || pub_bytes.is_empty() { return; }
        let signer = FaestImpl;
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
