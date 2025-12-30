//! As per https://signal.org/docs/specifications/mlkembraid/#state-machine-and-transitions
//! All states of the agents contain at least the following two variables:
//! - epoch: an unsigned integer identifying the epoch of the key being negotiated.
//! - auth: an Authenticator object.

use crate::{
    authenticator::Authenticator,
    erasure::{ErasureCodecDecode, ErasureCodecEncode},
    states::message::Epoch,
    wrapped_inc_mlkem768,
};

/// no additional state
#[derive(Clone)]
pub struct KeysUnsampled {
    pub epoch: Epoch,
    pub auth: Authenticator,
}

/// - dk: a KEM decapsulation key
/// - ek_vector: vector part of a KEM encapsulation key
/// - header_encoder
#[derive(Clone)]
pub struct KeysSampled {
    pub epoch: Epoch,
    pub auth: Authenticator,
    pub dk: wrapped_inc_mlkem768::DecapsulationKey,
    pub ek_vector: wrapped_inc_mlkem768::EncapsulationKey,
    pub header_encoder: ErasureCodecEncode,
}

/// - dk: a KEM decapsulation key
/// - ct1_decoder
/// - ek_encoder
#[derive(Clone)]
pub struct HeaderSent {
    pub epoch: Epoch,
    pub auth: Authenticator,
    pub dk: wrapped_inc_mlkem768::DecapsulationKey,
    pub ct1_decoder: ErasureCodecDecode,
    pub ek_encoder: ErasureCodecEncode,
}

/// - dk: a KEM decapsulation key
/// - ct1: The compressed public key part of a KEM ciphertext
/// - ek_encoder
#[derive(Clone)]
pub struct Ct1Received {
    pub epoch: Epoch,
    pub auth: Authenticator,
    pub dk: wrapped_inc_mlkem768::DecapsulationKey,
    pub ct1: wrapped_inc_mlkem768::Ciphertext1,
    pub ek_encoder: ErasureCodecEncode,
}

/// - dk: a KEM decapsulation key
/// - ct1: The compressed public key part of a KEM ciphertext
/// - ct2_decoder
#[derive(Clone)]
pub struct EkSentCt1Received {
    pub epoch: Epoch,
    pub auth: Authenticator,
    pub dk: wrapped_inc_mlkem768::DecapsulationKey,
    pub ct1: wrapped_inc_mlkem768::Ciphertext1,
    pub ct2_decoder: ErasureCodecDecode,
}
