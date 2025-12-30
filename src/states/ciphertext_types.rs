use crate::{
    authenticator::Authenticator,
    erasure::{ErasureCodecDecode, ErasureCodecEncode},
    states::{SHA3_256_SIZE, message::Epoch},
    wrapped_inc_mlkem768,
};

/// - header_decoder
#[derive(Clone)]
pub struct NoHeaderReceived {
    pub epoch: Epoch,
    pub auth: Authenticator,
    pub header_decoder: ErasureCodecDecode,
}

/// - ek_seed: seed of a KEM encapsulation key (aka: ek_header or hdr)
/// - hek: SHA3 hash of ek_seed || ek_vector
/// - ek_decoder
#[derive(Clone)]
pub struct HeaderReceived {
    pub epoch: Epoch,
    pub auth: Authenticator,
    /// (aka: ek_header or hdr)
    pub ek_seed: [u8; wrapped_inc_mlkem768::ENCAPS_SEED_SIZE],
    pub hek: [u8; SHA3_256_SIZE],
    pub ek_decoder: ErasureCodecDecode,
}

/// - ek_seed: seed of a KEM encapsulation key (aka: ek_header or hdr)
/// - hek: SHA3 hash of ek_seed || ek_vector
/// - encaps_secret: (state) the secret material used to encapsulate a KEM ciphertext
/// - ct1: The compressed public key part of a KEM ciphertext
/// - ct1_encoder
/// - ek_decoder
#[derive(Clone)]
pub struct Ct1Sampled {
    pub epoch: Epoch,
    pub auth: Authenticator,
    /// (aka: ek_header or hdr)
    pub ek_seed: [u8; wrapped_inc_mlkem768::ENCAPS_SEED_SIZE],
    pub hek: [u8; SHA3_256_SIZE],
    /// encapsulation state
    pub encaps_secret: wrapped_inc_mlkem768::EncapsulationState,
    pub ct1: wrapped_inc_mlkem768::Ciphertext1,
    pub ct1_encoder: ErasureCodecEncode,
    pub ek_decoder: ErasureCodecDecode,
}

/// - encaps_secret: the secret material used to encapsulate a KEM ciphertext
/// - ct1: The compressed public key part of a KEM ciphertext
/// - ek_seed (aka: ek_header or hdr)
/// - ek_vector
/// - ct1_encoder
#[derive(Clone)]
pub struct EkReceivedCt1Sampled {
    pub epoch: Epoch,
    pub auth: Authenticator,
    /// encapsulation state
    pub encaps_secret: wrapped_inc_mlkem768::EncapsulationState,
    pub ct1: wrapped_inc_mlkem768::Ciphertext1,
    /// (aka: ek_header or hdr)
    pub ek_seed: [u8; wrapped_inc_mlkem768::ENCAPS_SEED_SIZE],
    pub ek_vector: wrapped_inc_mlkem768::EncapsulationKey,
    pub ct1_encoder: ErasureCodecEncode,
}

/// - ek_seed: seed of a KEM encapsulation key (aka: ek_header or hdr)
/// - hek: SHA3 hash of ek_seed || ek_vector
/// - encaps_secret: the secret material used to encapsulate a KEM ciphertext
/// - ct1: The compressed public key part of a KEM ciphertext
/// - ek_decoder
#[derive(Clone)]
pub struct Ct1Acknowledged {
    pub epoch: Epoch,
    pub auth: Authenticator,
    /// (aka: ek_header or hdr)
    pub ek_seed: [u8; wrapped_inc_mlkem768::ENCAPS_SEED_SIZE],
    pub hek: [u8; SHA3_256_SIZE],
    /// encapsulation state
    pub encaps_secret: wrapped_inc_mlkem768::EncapsulationState,
    pub ct1: wrapped_inc_mlkem768::Ciphertext1,
    pub ek_decoder: ErasureCodecDecode,
}

/// - ct2_encoder
#[derive(Clone)]
pub struct Ct2Sampled {
    pub epoch: Epoch,
    pub auth: Authenticator,
    pub ct2_encoder: ErasureCodecEncode,
}
