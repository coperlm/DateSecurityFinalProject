use anyhow::{anyhow, Result};
use libc::size_t;
use std::os::raw::c_int;

// Constants mirrored from faest_256s.h
pub const FAEST_256S_PUBLIC_KEY_SIZE: usize = 48;
pub const FAEST_256S_PRIVATE_KEY_SIZE: usize = 48;
pub const FAEST_256S_SIGNATURE_SIZE: usize = 20696;

/// C-FFI error code from FAEST implementation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FaestError {
    KeygenFailed(c_int),
    SignFailed(c_int),
    InvalidPrivateKeySize { expected: usize, got: usize },
    InvalidPublicKeySize { expected: usize, got: usize },
}

impl std::fmt::Display for FaestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FaestError::KeygenFailed(code) => write!(f, "FAEST keygen failed (code={})", code),
            FaestError::SignFailed(code) => write!(f, "FAEST sign failed (code={})", code),
            FaestError::InvalidPrivateKeySize { expected, got } => write!(
                f,
                "FAEST invalid private key size: expected {}, got {}",
                expected, got
            ),
            FaestError::InvalidPublicKeySize { expected, got } => write!(
                f,
                "FAEST invalid public key size: expected {}, got {}",
                expected, got
            ),
        }
    }
}

impl std::error::Error for FaestError {}

extern "C" {
    pub fn faest_256s_keygen(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn faest_256s_sign(
        sk: *const u8,
        message: *const u8,
        message_len: size_t,
        signature: *mut u8,
        signature_len: *mut size_t,
    ) -> c_int;
    pub fn faest_256s_verify(
        pk: *const u8,
        message: *const u8,
        message_len: size_t,
        signature: *const u8,
        signature_len: size_t,
    ) -> c_int;
}

/// Generate a FAEST keypair (pk, sk)
pub fn keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; FAEST_256S_PUBLIC_KEY_SIZE];
    let mut sk = vec![0u8; FAEST_256S_PRIVATE_KEY_SIZE];
    let ret = unsafe { faest_256s_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if ret != 0 {
        Err(anyhow!(FaestError::KeygenFailed(ret)))
    } else {
        Ok((pk, sk))
    }
}

/// Sign a message with FAEST private key
pub fn sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != FAEST_256S_PRIVATE_KEY_SIZE {
        return Err(anyhow!(FaestError::InvalidPrivateKeySize {
            expected: FAEST_256S_PRIVATE_KEY_SIZE,
            got: sk.len(),
        }));
    }
    let mut sig = vec![0u8; FAEST_256S_SIGNATURE_SIZE];
    let mut sig_len: size_t = FAEST_256S_SIGNATURE_SIZE as size_t;
    let ret = unsafe {
        faest_256s_sign(
            sk.as_ptr(),
            message.as_ptr(),
            message.len() as size_t,
            sig.as_mut_ptr(),
            &mut sig_len as *mut size_t,
        )
    };
    if ret != 0 {
        Err(anyhow!(FaestError::SignFailed(ret)))
    } else {
        sig.truncate(sig_len as usize);
        Ok(sig)
    }
}

/// Verify a FAEST signature
pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    if pk.len() != FAEST_256S_PUBLIC_KEY_SIZE {
        return Err(anyhow!(FaestError::InvalidPublicKeySize {
            expected: FAEST_256S_PUBLIC_KEY_SIZE,
            got: pk.len(),
        }));
    }
    let ret = unsafe {
        faest_256s_verify(
            pk.as_ptr(),
            message.as_ptr(),
            message.len() as size_t,
            signature.as_ptr(),
            signature.len() as size_t,
        )
    };
    // 0 = 验证通过, 非0 = 验证失败（签名非法）。
    Ok(ret == 0)
}
