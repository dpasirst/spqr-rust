use crate::erasure::Chunk;

/// epoch (unsigned integer): Current epoch being negotiated
///
/// https://signal.org/docs/specifications/mlkembraid/#messages
pub type Epoch = u64;

/// type (enum): One of {None, Hdr, Ek, EkCt1Ack, Ct1Ack, Ct1, Ct2}
///
/// https://signal.org/docs/specifications/mlkembraid/#messages
#[derive(Debug, PartialEq, Eq)]
pub enum MessagePayloadType {
    /// None: There is no payload
    None,
    /// Hdr: The payload contains a chunk of the header.
    Hdr,
    /// Ek: The payload contains a chunk of the encapsulation key.
    Ek,
    /// EkCt1Ack: The payload contains a chunk of the encapsulation key, and the sender has completely received ct1.
    EkCt1Ack,
    /// Ct1Ack: No payload, but the sender has completely received ct1.
    Ct1Ack,
    /// Ct1: The payload contains a chunk of ct1.
    Ct1,
    /// Ct2: The payload contains a chunk of ct2.
    Ct2,
}

/// Messages consist of the following fields
///
/// In what follows we will describe messages logically using object
/// notation. Implementations may use a custom compact binary
/// format or a general purpose serialization tool such as Protocol
/// Buffers to encode these messages. In the presence of bandwidth
/// limits, implementers should consider that a custom format may
/// allow larger chunk sizes and correspondingly improve post-compromise
/// security [See Section 3.4](https://signal.org/docs/specifications/mlkembraid/#bandwidth-limits-message-sizes-and-speed-of-pcs).
///
/// https://signal.org/docs/specifications/mlkembraid/#messages
pub struct Message {
    pub epoch: Epoch,
    pub message_payload_type: MessagePayloadType,
    /// data (bytes, optional): Erasure code chunk when type is not one of { None, Ct1Ack }
    /// says, bytes but other parts of the spec call for chunk which requires an index
    /// so we will use chunk
    pub data: Option<Chunk>,
}
