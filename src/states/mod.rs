#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
#[cfg(not(feature = "std"))]
use core::error::Error;
#[cfg(feature = "std")]
use std::error::Error;

use crate::states::message::Epoch;

pub mod ciphertext_types;
pub mod ct_impl;
pub mod ek_impl;
pub mod encapsulation_key_types;
pub mod message;

pub const SHA3_256_SIZE: usize = 32;

// https://signal.org/docs/specifications/mlkembraid/#state-machine-and-transitions
pub enum State {
    // ek encapsulation Key
    /// an agent that is ready to sample a new KEM keypair on the next send event.
    /// no additional state
    ///
    /// When sending a message, the `KeysUnsampled` agent samples a new keypair,
    /// starts sending a header message, and transitions into the `KeysSampled`
    /// state. The `KeysUnsampled` agent ignores all messages it receives
    KeysUnsampled(encapsulation_key_types::KeysUnsampled),
    /// an agent that has sampled a KEM keypair and is sending the header
    /// - dk: a KEM decapsulation key
    /// - ek_vector: vector part of a KEM encapsulation key
    /// - header_encoder
    ///
    /// The `KeysSampled` agent sends chunks of the header. When it receives a
    /// message of type Ct1 it knows that the other party has received the
    /// complete header so it transitions into the `HeaderSent` state, in which
    /// it will begin sending chunks of ek_vector
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#keysunsampled
    KeysSampled(encapsulation_key_types::KeysSampled),
    /// an agent that has completed sending a header, is currently sending
    /// an ek_vector, and is receiving chunks of ct1
    /// - dk: a KEM decapsulation key
    /// - ct1_decoder
    /// - ek_encoder
    ///
    /// In the `HeaderSent` state, an agent sends chunks of its ek_vector.
    /// When receiving a message of type Ct1 for the current epoch, if
    /// it has enough chunks to decode the incoming ct1, it transitions
    /// to the `Ct1Received` state
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#keyssampled
    HeaderSent(encapsulation_key_types::HeaderSent),
    /// an agent that has completely received ct1 and is still sending
    /// chunks of ek_vector
    /// - dk: a KEM decapsulation key
    /// - ct1: The compressed public key part of a KEM ciphertext
    /// - ek_encoder
    ///
    /// In the `Ct1Received` state an agent sends chunks of the ek_vector
    /// until it receives a chunk of ct2. At that point it knows ek_vector
    /// has been received so it transitions into the `EkSentCt1Received` state
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#headersent
    Ct1Received(encapsulation_key_types::Ct1Received),
    /// an agent that has received ct1, sent ek, and is receiving chunks of ct2
    /// - dk: a KEM decapsulation key
    /// - ct1: The compressed public key part of a KEM ciphertext
    /// - ct2_decoder
    ///
    /// In the `EkSentCt1Received` state an agent doesn’t send any data
    /// to the other party and it receives chunks of ct2. Once ct2
    /// is received, it verifies the MAC, decapsulates the secret,
    /// emits the key, and transitions to the `NoHeaderReceived` state
    /// to wait for the other party to begin sending an encapsulation
    /// key for the next epoch
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#eksentct1received
    EkSentCt1Received(encapsulation_key_types::EkSentCt1Received),

    // ciphertext
    /// an agent that is receiving a header
    /// - header_decoder
    ///
    /// In the `NoHeaderReceived` state an agent receives chunks of the
    /// header. Once the header has been completely received, it
    /// transitions to the `HeaderReceived` state, but does not sample
    /// the ciphertext yet
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#noheaderreceived
    NoHeaderReceived(ciphertext_types::NoHeaderReceived),
    /// an agent that has received a header and is prepared to sample
    /// a new ct1 on the next send
    /// - ek_seed: seed of a KEM encapsulation key
    /// - hek: SHA3 hash of ek_seed || ek_vector
    /// - ek_decoder
    ///
    /// In the `HeaderReceived` state an agent is ready to sample a
    /// ciphertext when asked to send. When it does this, it computes
    /// the encapsulated shared secret for this epoch and returns
    /// it to the caller. While it has an ek_decoder prepared, it
    /// will not receive any ek_vector chunks until after it has
    /// sent a ct1 message - and then it will have transitioned out
    /// of this state. So the Receive function is a no-op
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#headerreceived
    HeaderReceived(ciphertext_types::HeaderReceived),
    /// an agent that has received a header, has sampled ct1, and
    /// is sending it in chunks
    /// - ek_seed: seed of a KEM encapsulation key
    /// - hek: SHA3 hash of ek_seed || ek_vector
    /// - encaps_secret: the secret material used to encapsulate a KEM ciphertext
    /// - ct1: The compressed public key part of a KEM ciphertext
    /// - ct1_encoder
    /// - ek_decoder
    ///
    /// The `Ct1Sampled` state has the most complex transition
    /// possibilities. In this state an agent is receiving chunks
    /// of ek_vector and sending chunks of ct1. If it receives all
    /// of ek_vector before receiving an acknowledgment that ct1
    /// was received, it will transition to `EkReceivedCt1Sampled`.
    /// On the other hand, if it receives an acknowledgment that
    /// ct1 was received before ek_vector has been completely
    /// received, it will transition to `Ct1Acknowledged`. If this
    /// agent both receives an acknowledgment for Ct1 and receives
    /// the last chunk of ek_vector in a single receive call, it
    /// will compute ct1 and transition to `Ct2Sampled`
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#ct1sampled
    Ct1Sampled(ciphertext_types::Ct1Sampled),
    /// an agent that has received an encapsulation key and is still
    /// sending ct1 in chunks
    /// - encaps_secret: the secret material used to encapsulate a KEM ciphertext
    /// - ct1: The compressed public key part of a KEM ciphertext
    /// - ek_seed
    /// - ek_vector
    /// - ct1_encoder
    ///
    /// In the `EkReceivedCt1Sampled` state an agent sends chunks of ct1 and
    /// awaits an acknowledgment that it has been received. When that
    /// acknowledgment comes, it computes ct2 and transitions to
    /// the `Ct2Sampled` state
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#ekreceivedct1sampled
    EkReceivedCt1Sampled(ciphertext_types::EkReceivedCt1Sampled),
    /// an agent that has completed sending ct1 but is still receiving
    /// chunks of ek_vector
    /// - ek_seed: seed of a KEM encapsulation key
    /// - hek: SHA3 hash of ek_seed || ek_vector
    /// - encaps_secret: the secret material used to encapsulate a KEM ciphertext
    /// - ct1: The compressed public key part of a KEM ciphertext
    /// - ek_decoder
    ///
    /// In the `Ct1Acknowledged` state an agent receives chunks of an
    /// incoming ek_vector. Once this has been completely received,
    /// it can compute ct2 and transition to the `Ct2Sampled` state
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#ct1acknowledged
    Ct1Acknowledged(ciphertext_types::Ct1Acknowledged),
    /// an agent that has completed sending ct1, received ek_vector,
    /// and is sending ct2
    /// - ct2_encoder
    ///
    /// In the `Ct2Sampled` state an agent sends chunks of ct2 and waits
    /// for a message from the next epoch. Once a message from the next
    /// epoch is received, it transitions to the `KeysUnsampled` state
    /// and prepares to start sending a new encapsulation key
    ///
    /// https://signal.org/docs/specifications/mlkembraid/#ct2sampled
    Ct2Sampled(ciphertext_types::Ct2Sampled),
}

/// as defined for Send(state) and Receive(state, msg)
/// output_key, a nullable pair containing an epoch identifier
/// and a shared secret for that epoch
pub struct OutputKey {
    pub epoch: Epoch,
    pub shared_secret: Vec<u8>,
}

pub struct StateSendResult {
    /// a none for state means we have not shifted to a new
    /// enum state; however, because state is passed as mut,
    /// the existing state may have changed
    pub state: Option<State>,
    pub msg: message::Message,
    pub sending_epoch: message::Epoch,
    pub output_key: Option<OutputKey>,
}
pub struct StateReceiveResult {
    /// a none for state means we have not shifted to a new
    /// enum state; however, because state is passed as mut,
    /// the existing state may have changed
    pub state: Option<State>,
    pub receiving_epoch: message::Epoch,
    pub output_key: Option<OutputKey>,
}

/// As per 1.1 Sparse Continuous Key Agreement
/// https://signal.org/docs/specifications/mlkembraid/#sparse-continuous-key-agreement
pub trait StateFunctions {
    /// Send(state) → (msg, sending_epoch, output_key): Updates the state
    /// and returns msg, a message to be processed by the other party,
    /// sending_epoch, the identifier of the latest epoch guaranteed
    /// to be known by the other party on receipt of msg, and output_key,
    /// a nullable pair containing an epoch identifier and a shared
    /// secret for that epoch.
    ///
    /// # Returns:
    /// (msg, sending_epoch, output_key)
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>>;

    /// Receive(state, msg) → (receiving_epoch, output_key): Updates the
    /// state and returns receiving_epoch, the epoch identifier that was
    /// output by the other party as sending_epoch when they called send()
    /// to generate msg, and output_key, a nullable pair containing an
    /// epoch identifier and a shared secret for that epoch.
    ///
    /// # Returns:
    /// (receiving_epoch, output_key)
    fn receive(&mut self, msg: message::Message) -> Result<StateReceiveResult, Box<dyn Error>>;
}
