#[cfg(not(feature = "std"))]
use alloc::{
    fmt::{self, Debug},
    vec::Vec,
};
#[cfg(not(feature = "std"))]
use core::error::Error;
#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{self, Debug},
};

use libcrux_hmac::hmac;

use crate::{
    PROTOCOL_INFO,
    kdf::{KdfError, kdf_auth},
    states::message::Epoch,
};

#[derive(Debug, Clone)]
pub enum AuthenticatorError {
    Kdf(KdfError),
    InvalidMacHeader,
    InvalidMacCipherText,
}

impl Error for AuthenticatorError {}

impl fmt::Display for AuthenticatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AuthenticatorError::{InvalidMacCipherText, InvalidMacHeader, Kdf};
        match self {
            Kdf(e) => write!(f, "Authenticator KDF: {e}"),
            InvalidMacCipherText => write!(f, "MAC is invalid for the CipherText"),
            InvalidMacHeader => write!(f, "MAC is invalid for the Encapsulation Key Header"),
        }
    }
}

/// While messaging protocols such as the Double Ratchet [2] provide
/// ratcheted message authentication through the use of AEAD or
/// explicit MACs on messages, it may be desirable for an SCKA
/// protocol to provide internal authenticity guarantees. We
/// attain this using a Ratcheted Authenticator.
///
/// https://signal.org/docs/specifications/mlkembraid/#internal-authentication
#[derive(Clone)]
pub struct Authenticator {
    /// a 32 byte value
    pub root_key: Vec<u8>,
    /// a 32 byte key for use with MAC
    pub mac_key: Vec<u8>,
}

// KDF_AUTH(root_key, update_key, epoch): 64 bytes of output from the HKDF algorithm [5] using hash with inputs:
// - HKDF input key material = update_key
// - HKDF salt = root_key
// - HKDF info = PROTOCOL_INFO || “:Authenticator Update” || ToBytes(epoch)
// - HKDF length = 64
// KDF_OK(shared_secret, epoch): 32 bytes of output from the HKDF algorithm [5] using hash with inputs:
// - HKDF input key material = shared_secret
// - HKDF salt = A zero-filled byte sequence with length equal to the hash output length, in bytes.
// - HKDF info = PROTOCOL_INFO || “:SCKA Key” || ToBytes(epoch)
// - HKDF length = 32
impl Authenticator {
    /// the spec calls for `MAC_SIZE` and talks about the mac being 32 bytes
    /// https://signal.org/docs/specifications/mlkembraid/#internal-authentication
    pub const MAC_SIZE: usize = 32;

    ///
    ///  def Authenticator.Init(auth_state, epoch, key):
    ///     auth_state = {root_key: '\0'*32, mac_key: None }
    ///     auth_state.Update(epoch, key)
    pub fn new(key: &[u8], epoch: Epoch) -> Result<Self, AuthenticatorError> {
        // start with 0's for the root and mac key
        let mut authenticator = Self {
            root_key: [0u8; 32].to_vec(),
            // ex. code called for None, but we are not optional
            mac_key: [0u8; 32].to_vec(),
        };
        // now update
        authenticator.update(epoch, key)?;
        Ok(authenticator)
    }

    // def Authenticator.Update(auth_state, epoch, key):
    //     auth_state.root_key, auth_state.mac_key
    //       = KDF_AUTH(auth_state.root_key, key, epoch)
    pub fn update(&mut self, epoch: Epoch, key: &[u8]) -> Result<(), AuthenticatorError> {
        let ikm = [self.root_key.as_slice(), key].concat();
        let mut okm = [0u8; 64];
        // KDF_AUTH
        kdf_auth(&mut okm, &self.root_key, &ikm, epoch).map_err(AuthenticatorError::Kdf)?;

        self.root_key = okm[..32].to_vec();
        self.mac_key = okm[32..].to_vec();
        Ok(())
    }

    /// ekheader
    ///
    /// def Authenticator.MacHdr(auth_state, epoch, hdr):
    ///     return MAC(
    ///         auth_state.mac_key,
    ///         PROTOCOL_INFO || ":ekheader" || epoch || hdr,
    ///         MAC_SIZE)
    pub fn mac_hdr(&self, epoch: Epoch, hdr: &[u8]) -> Vec<u8> {
        let hmac_data = [
            PROTOCOL_INFO.as_bytes(),
            b":ekheader".as_slice(),
            &epoch.to_be_bytes(),
            hdr,
        ]
        .concat();
        hmac(
            libcrux_hmac::Algorithm::Sha256,
            &self.mac_key,
            &hmac_data,
            Some(Self::MAC_SIZE),
        )
    }

    /// ciphertext
    ///
    ///  def Authenticator.MacCt(auth_state, epoch, ct):
    ///     return MAC(
    ///         auth_state.mac_key,
    ///         PROTOCOL_INFO || ":ciphertext" || epoch || ct,
    ///         MAC_SIZE)
    pub fn mac_ct(&self, epoch: Epoch, ct: &[u8]) -> Vec<u8> {
        let hmac_data = [
            PROTOCOL_INFO.as_bytes(),
            b":ciphertext".as_slice(),
            &epoch.to_be_bytes(),
            ct,
        ]
        .concat();
        hmac(
            libcrux_hmac::Algorithm::Sha256,
            &self.mac_key,
            &hmac_data,
            Some(Self::MAC_SIZE),
        )
    }

    /// verify header
    ///
    ///  def Authenticator.VfyHdr(auth_state, epoch, hdr, expected_mac):
    ///     if expected_mac != auth_state.MacHdr(epoch, hdr):
    ///         FAIL
    pub fn vfy_header(
        &self,
        epoch: Epoch,
        hdr: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), AuthenticatorError> {
        // no point in calculating if the size is incorrect
        if expected_mac.len() == Self::MAC_SIZE
            && Self::compare_ciphertexts_in_constant_time(expected_mac, &self.mac_hdr(epoch, hdr))
                == 0
        {
            return Ok(());
        }
        Err(AuthenticatorError::InvalidMacHeader)
    }

    /// verify CipherText
    ///
    ///  def Authenticator.VfyCt(auth_state, epoch, ct, expected_mac):
    ///     if expected_mac != auth_state.MacCt(epoch, ct):
    ///         FAIL
    pub fn vfy_ct(
        &self,
        epoch: Epoch,
        ct: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), AuthenticatorError> {
        // no point in calculating if the size is incorrect
        if expected_mac.len() == Self::MAC_SIZE
            && Self::compare_ciphertexts_in_constant_time(expected_mac, &self.mac_hdr(epoch, ct))
                == 0
        {
            return Ok(());
        }
        Err(AuthenticatorError::InvalidMacCipherText)
    }

    // The following is directly copied from: libcrux-ml-kem with the hax
    // parts removed. Had to copy it because it was not made available outside
    // of the crate itself
    //
    // https://github.com/cryspen/libcrux/blob/main/libcrux-ml-kem/src/constant_time_ops.rs

    /// https://github.com/cryspen/libcrux/blob/4d3a1a970dd8184c8039cf303473d94a143bde16/libcrux-ml-kem/src/constant_time_ops.rs#L100
    #[inline(never)] // Don't inline this to avoid that the compiler optimizes this out.
    fn compare_ciphertexts_in_constant_time(lhs: &[u8], rhs: &[u8]) -> u8 {
        // #[cfg(eurydice)]
        // return compare(lhs, rhs);

        //#[cfg(not(eurydice))]
        core::hint::black_box(Self::compare(lhs, rhs))
    }

    /// Return 1 if the bytes of `lhs` and `rhs` do not exactly
    /// match and 0 otherwise.
    ///
    /// https://github.com/cryspen/libcrux/blob/4d3a1a970dd8184c8039cf303473d94a143bde16/libcrux-ml-kem/src/constant_time_ops.rs#L46
    #[inline(never)] // Don't inline this to avoid that the compiler optimizes this out.
    fn compare(lhs: &[u8], rhs: &[u8]) -> u8 {
        let mut r: u8 = 0;
        for i in 0..lhs.len() {
            let nr = r | (lhs[i] ^ rhs[i]);
            r = nr;
        }
        Self::is_non_zero(r)
    }

    /// https://github.com/cryspen/libcrux/blob/4d3a1a970dd8184c8039cf303473d94a143bde16/libcrux-ml-kem/src/constant_time_ops.rs#L33
    #[inline(never)] // Don't inline this to avoid that the compiler optimizes this out.
    fn is_non_zero(value: u8) -> u8 {
        //#[cfg(eurydice)]
        //return inz(value);

        //#[cfg(not(eurydice))]
        core::hint::black_box(Self::inz(value))
    }

    /// Return 1 if `value` is not zero and 0 otherwise.
    ///
    /// https://github.com/cryspen/libcrux/blob/4d3a1a970dd8184c8039cf303473d94a143bde16/libcrux-ml-kem/src/constant_time_ops.rs#L16
    #[inline(never)] // Don't inline this to avoid that the compiler optimizes this out.
    fn inz(value: u8) -> u8 {
        let value = value as u16;
        let result = ((!value).wrapping_add(1) >> 8) as u8;
        result & 1
    }
}
