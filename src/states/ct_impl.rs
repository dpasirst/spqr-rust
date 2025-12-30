#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format};
#[cfg(not(feature = "std"))]
use core::error::Error;
use rand::TryRngCore as _;
use rand_core::OsRng;
#[cfg(feature = "std")]
use std::error::Error;

use crate::{
    authenticator::Authenticator,
    erasure::{ErasureCodecDecode, ErasureCodecEncode},
    kdf::kdf_ok,
    states::{
        OutputKey, State, StateFunctions, StateReceiveResult, StateSendResult,
        ciphertext_types::{
            Ct1Acknowledged, Ct1Sampled, Ct2Sampled, EkReceivedCt1Sampled, HeaderReceived,
            NoHeaderReceived,
        },
        encapsulation_key_types::KeysUnsampled,
        message::{Message, MessagePayloadType},
    },
    wrapped_inc_mlkem768,
};

impl NoHeaderReceived {
    /// we start with a shared_secret key in order to init Authenticator
    ///
    /// def InitBob(shared_secret):
    ///   epoch = 1
    ///   auth = Authenticator.Init(epoch, shared_secret)
    ///   header_decoder = Decoder.new(KEM.HEADER_SIZE + MAC_SIZE)
    ///   return NoHeaderReceived(epoch, auth, header_decoder)
    ///
    /// [Reference](https://signal.org/docs/specifications/mlkembraid/#initialization)
    pub fn new(shared_secret: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            epoch: 1,
            auth: Authenticator::new(shared_secret, 1)?,
            header_decoder: ErasureCodecDecode::new(
                wrapped_inc_mlkem768::HDR_SIZE + Authenticator::MAC_SIZE,
            ),
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#noheaderreceived
impl StateFunctions for NoHeaderReceived {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        //   # No data to send
        //   msg = {epoch: state.epoch, type: None}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::None,
            data: None,
        };

        //   # Return values
        //   output_key = None
        //   sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        //   return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: None,
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(&mut self, msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        //   output_key = None
        let output_key = None;
        //   receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        //   if msg.epoch == state.epoch and msg.type == Hdr:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::Ct2
            && let Some(chunk) = msg.data
        {
            // # Add chunk to decoder
            // state.header_decoder.add_chunk(msg.data)
            self.header_decoder.add_points(chunk);
            // # Check if header is complete
            // if state.header_decoder.has_message():
            //     header_with_mac = state.header_decoder.message()
            if let Some(header_with_mac) = self.header_decoder.recover() {
                if header_with_mac.len() != wrapped_inc_mlkem768::HDR_SIZE + Authenticator::MAC_SIZE
                {
                    return Err(format!(
                        "header_with_mac is not correct length, expected {}, found {}",
                        wrapped_inc_mlkem768::HDR_SIZE + Authenticator::MAC_SIZE,
                        header_with_mac.len()
                    )
                    .into());
                }
                // header = header_with_mac[:64]
                let header = &header_with_mac[..wrapped_inc_mlkem768::HDR_SIZE];
                // mac = header_with_mac[64:]
                let mac = &header_with_mac[wrapped_inc_mlkem768::HDR_SIZE..];
                // ek_seed = header[:32]
                let ek_seed = &header[..wrapped_inc_mlkem768::ENCAPS_SEED_SIZE];
                // hek = header[32:]
                // hek should be SHA3_256_SIZE
                let hek = &header[wrapped_inc_mlkem768::ENCAPS_SEED_SIZE..];

                // # Verify header MAC
                // state.auth.VfyHdr(state.epoch, header, mac)
                self.auth.vfy_header(self.epoch, header, mac)?;

                // # Prepare ek_vector decoder
                // ek_decoder = Decoder.new(KEM.EK_SIZE)
                let ek_decoder = ErasureCodecDecode::new(wrapped_inc_mlkem768::EK_SIZE);

                // # Update state
                // # Transition (6)
                // state = HeaderReceived(
                // state.epoch,
                // state.auth,
                // ek_seed,
                // hek,
                // ek_decoder)
                Some(State::HeaderReceived(HeaderReceived {
                    epoch: self.epoch,
                    auth: self.auth.clone(),
                    ek_seed: ek_seed.try_into()?,
                    hek: hek.try_into()?,
                    ek_decoder,
                }))
            } else {
                None
            }
        } else {
            None
        };
        //   return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: next_state,
            receiving_epoch,
            output_key,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#headerreceived
impl StateFunctions for HeaderReceived {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        //   # Generate shared secret and ct1
        //   (encaps_secret, ct1, ss) = KEM.Encaps1(state.ek_seed, state.hek)
        // this is not clear, what role does state.hek, play here? Encaps seems to
        // only want the header per section `1.2 Incremental KEMs`
        // TODO: investigate if hek is suppose to be included somehow?
        let mut rng = OsRng.unwrap_err();
        let (encaps_secret, ct1, ikm) =
            wrapped_inc_mlkem768::encaps1(&self.ek_seed.to_vec(), &mut rng)?;
        //   ss = KDF_OK(ss, state.epoch)
        let mut ss = [0u8; 32];
        kdf_ok(&mut ss, &ikm, self.epoch)?;

        //   # Update authenticator
        //   state.auth.Update(state.epoch, ss)
        self.auth.update(self.epoch, &ss)?;

        //   # Encode ct1 for transmission
        //   ct1_encoder = Encode(ct1)
        let mut ct1_encoder = ErasureCodecEncode::new(&ct1);
        //   chunk = ct1_encoder.next_chunk()
        let chunk = ct1_encoder.next_chunk();
        //   msg = {epoch: state.epoch, type: Ct1, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Ct1,
            data: Some(chunk),
        };

        //   # Update state
        //   # Transition (7)
        //   state = Ct1Sampled(
        //     state.epoch,
        //     state.auth,
        //     state.ek_seed,
        //     state.hek,
        //     encaps_secret,
        //     ct1,
        //     ct1_encoder,
        //     state.ek_decoder)
        let next_state = Some(State::Ct1Sampled(Ct1Sampled {
            epoch: self.epoch,
            auth: self.auth.clone(),
            ek_seed: self.ek_seed,
            hek: self.hek,
            encaps_secret,
            ct1,
            ct1_encoder,
            ek_decoder: self.ek_decoder.clone(),
        }));

        //   # Return values
        //   output_key = (state.epoch, ss)
        //   sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        //   return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: next_state,
            msg,
            sending_epoch,
            output_key: Some(OutputKey {
                epoch: self.epoch,
                shared_secret: ss.to_vec(),
            }),
        })
    }

    fn receive(&mut self, _msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        //   # No action taken
        //   output_key = None
        //   receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;
        //   return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: None,
            receiving_epoch,
            output_key: None,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#ct1sampled
impl StateFunctions for Ct1Sampled {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        // # Generate next ct1 chunk
        // chunk = state.ct1_encoder.next_chunk()
        let chunk = self.ct1_encoder.next_chunk();
        // msg = {epoch: state.epoch, type: Ct1, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Ct1,
            data: Some(chunk),
        };

        // # Return values
        // output_key = None
        // sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        // return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: None,
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(&mut self, msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        // output_key = None
        let output_key = None;
        // receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        // if msg.epoch == state.epoch and msg.type == Ek:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::Ek
            && let Some(chunk) = msg.data
        {
            // # Add ek_vector chunk
            // state.ek_decoder.add_chunk(msg.data)
            self.ek_decoder.add_points(chunk);
            // # Check if ek_vector is complete
            // if state.ek_decoder.has_message():
            //     ek_vector = state.ek_decoder.message()
            if let Some(ek_vector) = self.ek_decoder.recover() {
                // # Verify ek_vector integrity
                // if SHA3-256(state.ek_seed || ek_vector) != state.hek:
                //     raise Error("EK integrity check failed")
                let payload = [self.ek_seed.as_slice(), ek_vector.as_slice()].concat();
                if libcrux_sha3::sha3(libcrux_sha3::Algorithm::Sha256, &payload) != self.hek {
                    return Err("Ek: EK integrity check failed".into());
                }

                // # Update state
                // # Transition (10)
                // state = EkReceivedCt1Sampled(
                // state.epoch,
                // state.auth,
                // state.encaps_secret,
                // state.ct1,
                // state.ek_seed,
                // ek_vector,
                // state.ct1_encoder)
                Some(State::EkReceivedCt1Sampled(EkReceivedCt1Sampled {
                    epoch: self.epoch,
                    auth: self.auth.clone(),
                    encaps_secret: self.encaps_secret.clone(),
                    ct1: self.ct1.clone(),
                    ek_seed: self.ek_seed,
                    ek_vector,
                    ct1_encoder: self.ct1_encoder.clone(),
                }))
            } else {
                None
            }
        // elif msg.epoch == state.epoch and msg.type == EkCt1Ack:
        } else if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::EkCt1Ack
            && let Some(chunk) = msg.data
        {
            // # Add ek_vector chunk (with acknowledgment)
            // state.ek_decoder.add_chunk(msg.data)
            self.ek_decoder.add_points(chunk);

            // # Check if ek_vector is complete
            // if state.ek_decoder.has_message():
            //     ek_vector = state.ek_decoder.message()
            if let Some(ek_vector) = self.ek_decoder.recover() {
                // # Verify ek_vector integrity
                // if SHA3-256(state.ek_seed || ek_vector) != state.hek:
                //     raise Error("EK integrity check failed")
                let payload = [self.ek_seed.as_slice(), ek_vector.as_slice()].concat();
                if libcrux_sha3::sha3(libcrux_sha3::Algorithm::Sha256, &payload) != self.hek {
                    return Err("EkCt1Ack: EK integrity check failed".into());
                }

                // # Complete encapsulation
                // ct2 = KEM.Encaps2(
                // state.encaps_secret, state.ek_seed, ek_vector)
                // TODO: Investigate as this calls for both ek_seed and ek_vector, but encaps2 only uses ek_vector?
                let ct2 = wrapped_inc_mlkem768::encaps2(&self.encaps_secret, &ek_vector)?;
                // mac = state.auth.MacCt(state.epoch, state.ct1 || ct2)
                let mac = self
                    .auth
                    .mac_ct(self.epoch, &[self.ct1.as_slice(), ct2.as_slice()].concat());
                // ct2_encoder = Encode(ct2 || mac)
                let ct2_encoder =
                    ErasureCodecEncode::new(&[ct2.as_slice(), mac.as_slice()].concat());

                // # Update state
                // # Transition (9)
                // state = Ct2Sampled(state.epoch, state.auth, ct2_encoder)
                Some(State::Ct2Sampled(Ct2Sampled {
                    epoch: self.epoch,
                    auth: self.auth.clone(),
                    ct2_encoder,
                }))
            } else {
                None
            }
        } else {
            // # Update state
            // # Transition (8)
            // state = Ct1Acknowledged(
            // state.epoch,
            // state.auth,
            // state.encaps_secret,
            // state.ek_seed,
            // state.hek,
            // state.ct1,
            // state.ek_decoder)
            Some(State::Ct1Acknowledged(Ct1Acknowledged {
                epoch: self.epoch,
                auth: self.auth.clone(),
                ek_seed: self.ek_seed,
                hek: self.hek,
                encaps_secret: self.encaps_secret.clone(),
                ct1: self.ct1.clone(),
                ek_decoder: self.ek_decoder.clone(),
            }))
        };
        // return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: next_state,
            receiving_epoch,
            output_key,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#ekreceivedct1sampled
impl StateFunctions for EkReceivedCt1Sampled {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        // # Generate next ct1 chunk
        // chunk = state.ct1_encoder.next_chunk()
        let chunk = self.ct1_encoder.next_chunk();
        // msg = {epoch: state.epoch, type: Ct1, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Ct1,
            data: Some(chunk),
        };

        // # Return values
        // output_key = None
        // sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        // return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: None,
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(&mut self, msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        // output_key = None
        let output_key = None;
        // receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        // if msg.epoch == state.epoch and msg.type == EkCt1Ack:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::EkCt1Ack
        {
            // # Complete encapsulation
            // ct2 = KEM.Encaps2(
            // state.encaps_secret, state.ek_seed, state.ek_vector)
            // TODO: Investigate as this calls for both ek_seed and ek_vector, but encaps2 only uses ek_vector?
            let ct2 = wrapped_inc_mlkem768::encaps2(&self.encaps_secret, &self.ek_vector)?;
            // mac = state.auth.MacCt(state.epoch, state.ct1 || ct2)
            let mac = self
                .auth
                .mac_ct(self.epoch, &[self.ct1.as_slice(), ct2.as_slice()].concat());
            // ct2_encoder = Encode(ct2 || mac)
            let ct2_encoder = ErasureCodecEncode::new(&[ct2.as_slice(), mac.as_slice()].concat());
            // # Update state
            // # Transition (12)
            // state = Ct2Sampled(state.epoch, state.auth, ct2_encoder)
            Some(State::Ct2Sampled(Ct2Sampled {
                epoch: self.epoch,
                auth: self.auth.clone(),
                ct2_encoder,
            }))
        } else {
            None
        };
        // return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: next_state,
            receiving_epoch,
            output_key,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#ct1acknowledged
impl StateFunctions for Ct1Acknowledged {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        // # No data to send
        // msg = {epoch: state.epoch, type: None}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::None,
            data: None,
        };

        // # Return values
        // output_key = None
        // sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        // return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: None,
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(&mut self, msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        // output_key = None
        let output_key = None;
        // receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        // if msg.epoch == state.epoch and msg.type == EkCt1Ack:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::EkCt1Ack
            && let Some(chunk) = msg.data
        {
            // # Add ek_vector chunk
            // state.ek_decoder.add_chunk(msg.data)
            self.ek_decoder.add_points(chunk);

            // # Check if ek_vector is complete
            // if state.ek_decoder.has_message():
            //     ek_vector = state.ek_decoder.message()
            if let Some(ek_vector) = self.ek_decoder.recover() {
                // # Verify ek_vector integrity
                // if SHA3-256(state.ek_seed || ek_vector) != state.hek:
                //     raise Error("EK integrity check failed")
                let payload = [self.ek_seed.as_slice(), ek_vector.as_slice()].concat();
                if libcrux_sha3::sha3(libcrux_sha3::Algorithm::Sha256, &payload) != self.hek {
                    return Err("EkCt1Ack: EK integrity check failed".into());
                }

                // # Complete encapsulation
                // ct2 = KEM.Encaps2(
                // state.encaps_secret, state.ek_seed, ek_vector)
                // TODO: Investigate as this calls for both ek_seed and ek_vector, but encaps2 only uses ek_vector?
                let ct2 = wrapped_inc_mlkem768::encaps2(&self.encaps_secret, &ek_vector)?;
                // mac = state.auth.MacCt(state.epoch, state.ct1 || ct2)
                let mac = self
                    .auth
                    .mac_ct(self.epoch, &[self.ct1.as_slice(), ct2.as_slice()].concat());
                // ct2_encoder = Encode(ct2 || mac)
                let ct2_encoder =
                    ErasureCodecEncode::new(&[ct2.as_slice(), mac.as_slice()].concat());

                // # Update state
                // # Transition (11)
                // state = Ct2Sampled(state.epoch, state.auth, ct2_encoder)
                Some(State::Ct2Sampled(Ct2Sampled {
                    epoch: self.epoch,
                    auth: self.auth.clone(),
                    ct2_encoder,
                }))
            } else {
                None
            }
        } else {
            None
        };
        // return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: next_state,
            receiving_epoch,
            output_key,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#ct2sampled
impl StateFunctions for Ct2Sampled {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        // # Generate next ct2 chunk
        // chunk = state.ct2_encoder.next_chunk()
        let chunk = self.ct2_encoder.next_chunk();
        // msg = {epoch: state.epoch, type: Ct2, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Ct2,
            data: Some(chunk),
        };

        // # Return values
        // output_key = None
        // sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        // return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: None,
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(&mut self, msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        // output_key = None
        let output_key = None;

        // if msg.epoch == state.epoch + 1:
        let next_state = if msg.epoch == (self.epoch + 1) {
            // # Next epoch has begun
            // # Transition (13)
            // state = KeysUnsampled(state.epoch + 1, state.auth)
            Some(State::KeysUnsampled(KeysUnsampled {
                epoch: self.epoch + 1,
                auth: self.auth.clone(),
            }))
        } else {
            None
        };

        // receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;
        // return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: next_state,
            receiving_epoch,
            output_key,
        })
    }
}
