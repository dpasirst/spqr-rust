#[cfg(not(feature = "std"))]
use alloc::{
    fmt::{self, Debug},
    format,
    string::String,
};
#[cfg(not(feature = "std"))]
use core::error::Error;
#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{self, Debug},
};

use libcrux_hkdf::hkdf;

use crate::{PROTOCOL_INFO, states::message::Epoch};

#[derive(Debug, Clone)]
pub enum KdfError {
    KdfAuth(String),
    KdfOk(String),
}

impl Error for KdfError {}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use KdfError::{KdfAuth, KdfOk};
        match self {
            KdfAuth(e) => write!(f, "KdfAuth HKDF {e}"),
            KdfOk(e) => write!(f, "KdfOk HKDF {e}"),
        }
    }
}

/// KDF_AUTH(root_key, update_key, epoch): 64 bytes of output from the HKDF algorithm [5] using hash with inputs:
/// - HKDF input key material = update_key
/// - HKDF salt = root_key
/// - HKDF info = PROTOCOL_INFO || “:Authenticator Update” || ToBytes(epoch)
/// - HKDF length = 64
pub fn kdf_auth(okm: &mut [u8], salt: &[u8], ikm: &[u8], epoch: Epoch) -> Result<(), KdfError> {
    let info = [
        PROTOCOL_INFO.as_bytes(),
        b":Authenticator Update".as_slice(),
        &epoch.to_be_bytes(),
    ]
    .concat();
    hkdf(libcrux_hkdf::Algorithm::Sha256, okm, salt, ikm, &info)
        .map_err(|e| KdfError::KdfAuth(format!("{:#?}", e)))
}

/// KDF_OK(shared_secret, epoch): 32 bytes of output from the HKDF algorithm [5] using hash with inputs:
/// - HKDF input key material = shared_secret
/// - HKDF salt = A zero-filled byte sequence with length equal to the hash output length, in bytes.
/// - HKDF info = PROTOCOL_INFO || “:SCKA Key” || ToBytes(epoch)
/// - HKDF length = 32
pub fn kdf_ok(okm: &mut [u8], ikm: &[u8], epoch: Epoch) -> Result<(), KdfError> {
    let info = [
        PROTOCOL_INFO.as_bytes(),
        b":SCKA Key".as_slice(),
        &epoch.to_be_bytes(),
    ]
    .concat();
    hkdf(libcrux_hkdf::Algorithm::Sha256, okm, &[0u8; 32], ikm, &info)
        .map_err(|e| KdfError::KdfAuth(format!("{:#?}", e)))
}
