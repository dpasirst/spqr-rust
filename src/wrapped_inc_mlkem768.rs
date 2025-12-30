//! Wrapped libcrux-ml-kem 768 with the incremental feature
//!
//! ML-KEM [1] encapsulation keys consist of a 32-byte seed followed
//! by a larger noisy vector. This seed is required to compute the
//! “compressed public key” part of a ciphertext, ct1. Due to the
//! Fujisaki-Okamoto transform [4] variant used by ML-KEM, we also need
//! to know the SHA3-256 hash of the full encapsulation key to compute ct1.
//!
//! [Reference 1](https://signal.org/docs/specifications/mlkembraid/#incremental-kems)
//! [Reference 2](https://signal.org/docs/specifications/mlkembraid/#ml-kem-as-an-incremental-kem)
//!

use libcrux_ml_kem::mlkem768::incremental;
use rand::{CryptoRng, Rng};

#[cfg(not(feature = "std"))]
use alloc::{
    fmt::{self, Debug},
    format,
    string::String,
    vec,
    vec::Vec,
};
#[cfg(not(feature = "std"))]
use core::error::Error;
#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{self, Debug},
};

#[derive(Debug, Clone)]
pub enum IncrementalMlKemError {
    Encaps1Error(String),
    Encaps2Error(String),
    DencapsError(String),
}

impl Error for IncrementalMlKemError {}

impl fmt::Display for IncrementalMlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IncrementalMlKemError::{DencapsError, Encaps1Error, Encaps2Error};
        match self {
            Encaps1Error(e) => write!(f, "Encapsulation1 Error {e}"),
            Encaps2Error(e) => write!(f, "Encapsulation2 Error {e}"),
            DencapsError(e) => write!(f, "Decapsulation Error {e}"),
        }
    }
}

// Types
/// ek (pk2)
pub type EncapsulationKey = Vec<u8>;
/// dk (sk)
pub type DecapsulationKey = Vec<u8>;
/// ct1
pub type Ciphertext1 = Vec<u8>;
/// ct2
pub type Ciphertext2 = Vec<u8>;
/// encaps_state
pub type EncapsulationState = Vec<u8>;
/// hdr (pk1)
pub type Header = Vec<u8>;
// shared_secret
pub type SharedSecret = [u8; SHARED_SECRET_SIZE];

// Const
pub const EK_SIZE: usize = incremental::pk2_len();
pub const CT1_SIZE: usize = incremental::Ciphertext1::len();
pub const CT2_SIZE: usize = incremental::Ciphertext2::len();
pub const ENCAPS_SIZE: usize = incremental::encaps_state_len();
pub const HDR_SIZE: usize = incremental::pk1_len();
pub const ENCAPS_SEED_SIZE: usize = libcrux_ml_kem::ENCAPS_SEED_SIZE;
pub const SHARED_SECRET_SIZE: usize = libcrux_ml_kem::SHARED_SECRET_SIZE;

pub struct KeySet {
    /// ek (pk2)
    pub ek: EncapsulationKey,
    /// dk (sk)
    pub dk: DecapsulationKey,
    /// hdr (pk1)
    pub hdr: Header,
}

/// KeyGen(randomness) → (dk, ek_header, ek_vector): Takes an array of
/// random bits and returns a decapsulation key, dk, an ek_header with
/// all information needed for a recipient to calculate ct1, and the “vector”
/// part of the encapsulation key, ek_vector. We note that for some KEMs it
/// is possible that the header could be empty.
pub fn key_gen<R: Rng + CryptoRng>(rng: &mut R) -> KeySet {
    // 1. start with entropy filled buffer
    let mut rand_buff = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
    rng.fill_bytes(&mut rand_buff);
    // 2. generate compressed keyset
    let compressed_ks = incremental::KeyPairCompressedBytes::from_seed(rand_buff);
    KeySet {
        ek: compressed_ks.pk2().to_vec(),
        dk: compressed_ks.sk().to_vec(),
        hdr: compressed_ks.pk1().to_vec(),
    }
}

/// Validate that the two parts Header (hdr) and EncapsulationKey (ek)
/// are consistent.
///
/// # Parameters:
/// - `ek` is the `EncapsulationKey` also known as `pk2`
/// - `hdr` is the `Header` also known as `pk1`
///
/// # Returns:
/// - `true` if the validation succeeds, else `false`
pub fn validate_ek_to_header(ek: &EncapsulationKey, hdr: &Header) -> bool {
    incremental::validate_pk_bytes(hdr, ek).is_ok()
}

/// Encaps1(ek_header, randomness) → (encaps_secret, ct1, shared_secret):
/// Takes an encapsulation key header and an array of random bits
/// as input and samples the first part of a new ciphertext. It
/// returns encaps_secret (state), an encapsulation secret that holds
/// the information needed to complete the encapsulation, ct1,
/// the first component of a ciphertext, and shared_secret, the
/// shared secret encapsulated by the ciphertext.
///
/// # Parameters
/// - `hdr` is the Header (pk1)
///
/// # Returns
/// (EncapsulationState, Ciphertext1, Vec<u8> /* shared_secret */)
///
/// # Errors
/// IncrementalMlKemError
pub fn encaps1<R: Rng + CryptoRng>(
    hdr: &Header, // pk1
    rng: &mut R,
) -> Result<(EncapsulationState, Ciphertext1, SharedSecret), IncrementalMlKemError> {
    // 1. start with entropy filled buffer
    let mut rand_buff = [0u8; SHARED_SECRET_SIZE];
    rng.fill_bytes(&mut rand_buff);
    // 2. populate the encaps_secret (encaps_state) and the shared_secret
    let mut encaps_state = vec![0u8; ENCAPS_SIZE];
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    let ct1 = incremental::encapsulate1(hdr, rand_buff, &mut encaps_state, &mut shared_secret)
        .map_err(|e| IncrementalMlKemError::Encaps1Error(format!("{:#?}", e)))?;
    Ok((encaps_state, ct1.value.to_vec(), shared_secret))
}

/// Encaps2(encaps_secret (state), ek_header, ek_vector (ek)) → ct2:
/// Takes an encapsulation secret, encapsulation key header, and
/// encapsulation key vector and completes the encapsulation
/// process, returning a reconciliation message, ct2.
///
/// Observation, using `libcrux-ml-crux`'s `encapsulate2()` only
/// take `state` and `ek` (state, public_key_part) thus the
/// ek_header and ek_vector are one
///
/// # Parameters
/// - `encaps_state` is the `state`
/// - `ek` is the public_key_part/header (pk1)
///
/// # Returns
/// Ciphertext2
///
/// # Errors
/// IncrementalMlKemError
pub fn encaps2(
    encaps_state: &EncapsulationState,
    ek: &EncapsulationKey,
) -> Result<Ciphertext2, IncrementalMlKemError> {
    let ct2 = incremental::encapsulate2(
        encaps_state
            .as_slice()
            .try_into()
            .map_err(|e| IncrementalMlKemError::Encaps2Error(format!("State: {e}")))?,
        ek.as_slice()
            .try_into()
            .map_err(|e| IncrementalMlKemError::Encaps2Error(format!("Ek public_key_part: {e}")))?,
    );
    Ok(ct2.value.to_vec())
}

/// Decaps(dk, ct1, ct2) → shared_secret: Takes a decapsulation key
/// and a complete ciphertext and returns the encapsulated shared secret.
///
/// # Parameters
/// - `dk` decapsulation key (sk or private_key)
/// - `ct1` ciphertext1
/// - `ct2` ciphertext2
///
/// # Returns
/// shared_secret (SharedSecret)
///
/// # Errors
/// IncrementalMlKemError
pub fn decaps(
    dk: &DecapsulationKey,
    ct1: &Ciphertext1,
    ct2: &Ciphertext2,
) -> Result<SharedSecret, IncrementalMlKemError> {
    Ok(incremental::decapsulate_compressed_key(
        dk.as_slice()
            .try_into()
            .map_err(|e| IncrementalMlKemError::DencapsError(format!("dk: {e}")))?,
        &incremental::Ciphertext1 {
            value: ct1
                .as_slice()
                .try_into()
                .map_err(|e| IncrementalMlKemError::DencapsError(format!("ct1: {e}")))?,
        },
        &incremental::Ciphertext2 {
            value: ct2
                .as_slice()
                .try_into()
                .map_err(|e| IncrementalMlKemError::DencapsError(format!("ct2: {e}")))?,
        },
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::TryRngCore;
    use rand_core::OsRng;

    fn gen_keyset() -> KeySet {
        let mut rng = OsRng.unwrap_err();
        key_gen(&mut rng)
    }

    #[test]
    fn validate_test() {
        let ks = gen_keyset();
        assert!(validate_ek_to_header(&ks.ek, &ks.hdr))
    }

    #[test]
    fn mlkem_test() -> Result<(), IncrementalMlKemError> {
        // alice:: key_gen
        let ks = gen_keyset();
        // alice sends hdr to bob
        // bob: encaps1
        let mut rng = OsRng.unwrap_err();
        let (encaps_state, ct1, bob_shared_secret) = encaps1(&ks.hdr, &mut rng)?;
        // bob: encaps2
        let ct2 = encaps2(&encaps_state, &ks.ek)?;
        // alice: decaps
        let alice_shared_secret = decaps(&ks.dk, &ct1, &ct2)?;
        // both now have the same shared secret
        assert_eq!(alice_shared_secret, bob_shared_secret);
        Ok(())
    }
}
