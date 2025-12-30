#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format};
#[cfg(not(feature = "std"))]
use core::error::Error;
#[cfg(feature = "std")]
use std::error::Error;

use crate::{
    authenticator::Authenticator,
    erasure::{ErasureCodecDecode, ErasureCodecEncode},
    kdf::kdf_ok,
    states::{
        OutputKey, SHA3_256_SIZE, State, StateFunctions, StateReceiveResult, StateSendResult,
        ciphertext_types::NoHeaderReceived,
        encapsulation_key_types::{
            Ct1Received, EkSentCt1Received, HeaderSent, KeysSampled, KeysUnsampled,
        },
        message::{Message, MessagePayloadType},
    },
    wrapped_inc_mlkem768,
};

use rand::TryRngCore;
use rand_core::OsRng;

impl KeysUnsampled {
    /// we start with a shared_secret key in order to init Authenticator
    ///
    /// def InitAlice(shared_secret):
    ///   epoch = 1
    ///   auth = Authenticator.Init(epoch, shared_secret)
    ///   return KeysUnsampled(epoch, auth)
    ///
    /// [Reference](https://signal.org/docs/specifications/mlkembraid/#initialization)
    pub fn new(shared_secret: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            epoch: 1,
            auth: Authenticator::new(shared_secret, 1)?,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#keysunsampled
impl StateFunctions for KeysUnsampled {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        let mut rng = OsRng.unwrap_err();
        // (dk, ek_seed, ek_vector) = KEM.KeyGen()
        let ks = wrapped_inc_mlkem768::key_gen(&mut rng);
        // hek = SHA3-256(ek_seed || ek_vector)
        let payload = [ks.hdr.as_slice(), ks.ek.as_slice()].concat();
        let hek: [u8; SHA3_256_SIZE] =
            libcrux_sha3::sha3(libcrux_sha3::Algorithm::Sha256, &payload);
        // header = ek_seed || hek
        let header = [ks.hdr.as_slice(), &hek].concat();
        // mac = state.auth.MacHdr(state.epoch, header)
        let mac = self.auth.mac_hdr(self.epoch, &header);
        // header_encoder = Encode(header || mac)
        let message = [header.as_slice(), mac.as_slice()].concat();
        let mut header_encoder = ErasureCodecEncode::new(&message);

        // Generate message
        //chunk = header_encoder.next_chunk()
        let chunk = header_encoder.next_chunk();
        //msg = {epoch: state.epoch, type: Hdr, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Hdr,
            data: Some(chunk),
        };

        //# Update state
        // # Transition (1)
        // state = KeysSampled(
        //     state.epoch,
        //     state.auth,
        //     dk,
        //     ek_seed,
        //     ek_vector,
        //     hek,
        //     header_encoder)
        let next_state = KeysSampled {
            epoch: self.epoch,
            auth: self.auth.clone(),
            dk: ks.dk,
            ek_vector: ks.ek,
            header_encoder,
        };

        //# Return values
        // output_key = None
        // sending_epoch = state.epoch - 1
        let sending_epoch = self.epoch - 1;
        // return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: Some(State::KeysSampled(next_state)),
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(&mut self, _msg: Message) -> Result<StateReceiveResult, Box<dyn Error>> {
        // # No action taken
        //   output_key = None
        //   receiving_epoch = state.epoch - 1
        //   return (receiving_epoch, output_key)
        Ok(StateReceiveResult {
            state: None,
            receiving_epoch: self.epoch - 1,
            output_key: None,
        })
    }
}

/// https://signal.org/docs/specifications/mlkembraid/#keyssampled
impl StateFunctions for KeysSampled {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        //   # Generate next header chunk
        //   chunk = state.header_encoder.next_chunk()
        let chunk = self.header_encoder.next_chunk();
        //   msg = {epoch: state.epoch, type: Hdr, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Hdr,
            data: Some(chunk),
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

    fn receive(
        &mut self,
        msg: super::message::Message,
    ) -> Result<StateReceiveResult, Box<dyn Error>> {
        //   output_key = None
        let output_key = None;
        //   receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        //   if msg.epoch == state.epoch and msg.type == Ct1:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::Ct1
            && let Some(chunk) = msg.data
        {
            //       # Initialize ct1 decoder and ek encoder
            //       ct1_decoder = Decoder.new(KEM.CT1_SIZE)
            let mut ct1_decoder = ErasureCodecDecode::new(wrapped_inc_mlkem768::CT1_SIZE);
            //       ct1_decoder.add_chunk(msg.data)
            ct1_decoder.add_points(chunk);
            //       ek_encoder = Encode(state.ek_vector)
            let ek_encoder = ErasureCodecEncode::new(&self.ek_vector);

            //       # Update state
            //       # Transition (2)
            //       state = HeaderSent(
            //         state.epoch,
            //         state.auth,
            //         state.dk,
            //         ct1_decoder,
            //         ek_encoder)
            Some(State::HeaderSent(HeaderSent {
                epoch: self.epoch,
                auth: self.auth.clone(),
                dk: self.dk.clone(),
                ct1_decoder,
                ek_encoder,
            }))
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

/// https://signal.org/docs/specifications/mlkembraid/#headersent
impl StateFunctions for HeaderSent {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        //   # Generate next ek_vector chunk
        //   chunk = state.ek_encoder.next_chunk()
        let chunk = self.ek_encoder.next_chunk();
        //   msg = {epoch: state.epoch, type: Ek, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::Ek,
            data: Some(chunk),
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

    fn receive(
        &mut self,
        msg: super::message::Message,
    ) -> Result<StateReceiveResult, Box<dyn Error>> {
        //   output_key = None
        let output_key = None;
        //   receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        //   if msg.epoch == state.epoch and msg.type == Ct1:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::Ct1
            && let Some(chunk) = msg.data
        {
            //       # Add chunk to decoder
            //       state.ct1_decoder.add_chunk(msg.data)
            self.ct1_decoder.add_points(chunk);

            //       # Check if ct1 is complete
            //       if state.ct1_decoder.has_message():
            //           ct1 = state.ct1_decoder.message()
            // no need to check twice, `.recover()` will check if it can
            // recover the message as the first step
            if let Some(ct1) = self.ct1_decoder.recover() {
                //           # Update state
                //           # Transition (3)
                //           state = Ct1Received(
                //             state.epoch,
                //             state.auth,
                //             state.dk,
                //             ct1,
                //             state.ek_encoder)
                Some(State::Ct1Received(Ct1Received {
                    epoch: self.epoch,
                    auth: self.auth.clone(),
                    dk: self.dk.clone(),
                    ct1,
                    ek_encoder: self.ek_encoder.clone(),
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

/// https://signal.org/docs/specifications/mlkembraid/#ct1received
impl StateFunctions for Ct1Received {
    fn send(&mut self) -> Result<StateSendResult, Box<dyn Error>> {
        //   # Generate next ek_vector chunk with acknowledgment
        //   chunk = state.ek_encoder.next_chunk()
        let chunk = self.ek_encoder.next_chunk();
        //   msg = {epoch: state.epoch, type: EkCt1Ack, data: chunk}
        let msg = Message {
            epoch: self.epoch,
            message_payload_type: MessagePayloadType::EkCt1Ack,
            data: Some(chunk),
        };

        //   # Return values
        //   output_key = None
        let sending_epoch = self.epoch - 1;
        //   return (msg, sending_epoch, output_key)
        Ok(StateSendResult {
            state: None,
            msg,
            sending_epoch,
            output_key: None,
        })
    }

    fn receive(
        &mut self,
        msg: super::message::Message,
    ) -> Result<StateReceiveResult, Box<dyn Error>> {
        //   output_key = None
        let output_key = None;
        //   receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        //   if msg.epoch == state.epoch and msg.type == Ct2:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::Ct2
            && let Some(chunk) = msg.data
        {
            //       # Initialize ct2 decoder
            //       ct2_decoder = Decoder.new(KEM.CT2_SIZE + MAC_SIZE)
            let mut ct2_decoder =
                ErasureCodecDecode::new(wrapped_inc_mlkem768::CT2_SIZE + Authenticator::MAC_SIZE);
            //       ct2_decoder.add_chunk(msg.data)
            ct2_decoder.add_points(chunk);

            //       # Update state
            //       # Transition (4)
            //       state = EkSentCt1Received(
            //         state.epoch,
            //         state.auth,
            //         state.dk,
            //         state.ct1,
            //         ct2_decoder)
            Some(State::EkSentCt1Received(EkSentCt1Received {
                epoch: self.epoch,
                auth: self.auth.clone(),
                dk: self.dk.clone(),
                ct1: self.ct1.clone(),
                ct2_decoder,
            }))
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

/// https://signal.org/docs/specifications/mlkembraid/#eksentct1received
impl StateFunctions for EkSentCt1Received {
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

    fn receive(
        &mut self,
        msg: super::message::Message,
    ) -> Result<StateReceiveResult, Box<dyn Error>> {
        //   output_key = None
        let mut output_key = None;
        //   receiving_epoch = state.epoch - 1
        let receiving_epoch = self.epoch - 1;

        //   if msg.epoch == state.epoch and msg.type == Ct2:
        let next_state = if msg.epoch == self.epoch
            && msg.message_payload_type == MessagePayloadType::Ct2
            && let Some(chunk) = msg.data
        {
            // # Add chunk to decoder
            // state.ct2_decoder.add_chunk(msg.data)
            self.ct2_decoder.add_points(chunk);
            // # Check if ct2 is complete
            // if state.ct2_decoder.has_message():
            //     ct2_with_mac = state.ct2_decoder.message()
            if let Some(ct2_with_mac) = self.ct2_decoder.recover() {
                if ct2_with_mac.len() != (wrapped_inc_mlkem768::CT2_SIZE + Authenticator::MAC_SIZE)
                {
                    return Err(format!(
                        "Incorrect ct2_with_mac length, expected {}, found {}",
                        wrapped_inc_mlkem768::CT2_SIZE + Authenticator::MAC_SIZE,
                        ct2_with_mac.len()
                    )
                    .into());
                }
                // ct2 = ct2_with_mac[:KEM.CT2_SIZE]
                let ct2 = &ct2_with_mac[..wrapped_inc_mlkem768::CT2_SIZE].to_vec();
                // mac = ct2_with_mac[KEM.CT2_SIZE:]
                let mac = &ct2_with_mac[wrapped_inc_mlkem768::CT2_SIZE..];

                // # Decapsulate shared secret
                // ss = KEM.Decaps(state.dk, state.ct1, ct2)
                let ikm = wrapped_inc_mlkem768::decaps(&self.dk, &self.ct1, ct2)?;
                // ss = KDF_OK(ss, state.epoch)
                let mut ss = [0u8; 32];
                kdf_ok(&mut ss, &ikm, self.epoch)?;

                // # Update authenticator and verify MAC
                // state.auth.Update(state.epoch, ss)
                self.auth.update(self.epoch, &ss)?;
                // state.auth.VfyCt(state.epoch, state.ct1 || ct2, mac)
                self.auth.vfy_ct(
                    self.epoch,
                    &[self.ct1.as_slice(), ct2_with_mac.as_slice()].concat(),
                    mac,
                )?;

                // # Prepare for next epoch
                // header_decoder = Decoder.new(KEM.HEADER_SIZE + MAC_SIZE)
                let header_decoder = ErasureCodecDecode::new(
                    wrapped_inc_mlkem768::HDR_SIZE + Authenticator::MAC_SIZE,
                );

                // # Update state and return key
                // # Transition (5)
                // state = NoHeaderReceived(
                // state.epoch + 1,
                // state.auth,
                // header_decoder)
                // output_key = (state.epoch - 1, ss)
                output_key = Some(OutputKey {
                    epoch: self.epoch - 1,
                    shared_secret: ss.to_vec(),
                });
                Some(State::NoHeaderReceived(NoHeaderReceived {
                    epoch: self.epoch + 1,
                    auth: self.auth.clone(),
                    header_decoder,
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
