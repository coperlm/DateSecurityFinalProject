use crate::crypto::ChameleonHash;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::PathBuf;
use tokio::sync::RwLock;

/// 全局共享状态
pub struct AppState {
    pub ch: ChameleonHash,
    pub chain: RwLock<crate::chain::Blockchain>,
    pub admin_rsa_pub: RsaPublicKey,
    pub admin_rsa_priv: RsaPrivateKey,
    pub chain_file: PathBuf,
}

/// 生成在线操作 ID
pub fn new_uuid() -> String {
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
