//! WebSocket protocol implementation.
//! This module provides the necessary types and functions to work with the WebSocket
//! protocol, including framing, encoding, and decoding.

use rand::{Rng, SeedableRng};
use tokio_util::bytes::Buf as _;

const FIN_MASK: u8 = 0x80;
const RSV_MASK: u8 = 0x70;
const OPCODE_MASK: u8 = 0x0F;
const MASKBIT_MASK: u8 = 0x80;
const LENGTH_MASK: u8 = 0x7F;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    ContinuationFrame = 0x0,
    TextFrame = 0x1,
    BinaryFrame = 0x2,
    ConnectionClose = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl TryFrom<u8> for Opcode {
    type Error = WebsocketCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(Self::ContinuationFrame),
            0x1 => Ok(Self::TextFrame),
            0x2 => Ok(Self::BinaryFrame),
            0x8 => Ok(Self::ConnectionClose),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            x => Err(WebsocketCodecError::UnknownOpcode(x)),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::ContinuationFrame => 0x00,
            Opcode::TextFrame => 0x01,
            Opcode::BinaryFrame => 0x02,
            Opcode::ConnectionClose => 0x08,
            Opcode::Ping => 0x09,
            Opcode::Pong => 0x0A,
        }
    }
}

use crate::errors::WebsocketCodecError;

#[derive(Clone, Debug)]
pub struct WebsocketFrame {
    pub(crate) fin: bool,
    pub(crate) opcode: Opcode,
    pub(crate) payload: Vec<u8>,
}

#[allow(
    dead_code,
    reason = "Will be used if module is extracted into a crate."
)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EndpointType {
    Client,
    Server,
}

#[derive(Debug)]
pub struct WebsocketCodec {
    endpoint_type: EndpointType,
    max_length: usize,
    rng: rand::rngs::StdRng,
}

impl WebsocketCodec {
    /// Create a new WebSocket codec.
    ///
    /// `endpoint_type` specifies whether this codec is for a client or server.
    /// `max_length` specifies the maximum allowed payload length for incoming frames.
    /// Frames exceeding this length will result in a `SizeError`.
    #[must_use]
    pub fn new(endpoint_type: EndpointType, max_length: usize) -> Self {
        let rng = rand::rngs::StdRng::from_os_rng();
        Self {
            endpoint_type,
            max_length,
            rng,
        }
    }
}

impl tokio_util::codec::Decoder for WebsocketCodec {
    type Item = WebsocketFrame;
    type Error = WebsocketCodecError;

    fn decode(
        &mut self,
        src: &mut tokio_util::bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }

        let fin = src[0] & FIN_MASK != 0;
        if src[0] & RSV_MASK != 0 {
            return Err(WebsocketCodecError::ProtocolViolation(
                "One or more RSV flag(s) set",
            ));
        }
        let opcode = (src[0] & OPCODE_MASK).try_into()?;
        let masked = src[1] & MASKBIT_MASK != 0;
        let length_flag = src[1] & 0x7F;

        // Check masking rules
        match self.endpoint_type {
            EndpointType::Client if masked => {
                return Err(WebsocketCodecError::ProtocolViolation(
                    "Client must not receive masked frames",
                ));
            }
            EndpointType::Server if !masked => {
                return Err(WebsocketCodecError::ProtocolViolation(
                    "Server must receive masked frames",
                ));
            }
            _ => {}
        }

        let (header_len, payload_len) = match length_flag & LENGTH_MASK {
            0..=125 => (2, length_flag as usize),
            126 => {
                if src.len() < 4 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([src[2], src[3]]) as usize;
                (4, len)
            }
            127 => {
                if src.len() < 10 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    src[2], src[3], src[4], src[5], src[6], src[7], src[8], src[9],
                ]);
                if len > self.max_length as u64
                    || len > 0x8000_0000_0000_0000
                    || len > usize::MAX as u64
                {
                    return Err(WebsocketCodecError::SizeError(len));
                }
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "Checked above; safe for all platforms"
                )]
                (10, len as usize)
            }
            128.. => unreachable!(),
        };

        let mask_len = if masked { 4 } else { 0 };
        let total_len = header_len + mask_len + payload_len;
        if src.len() < total_len {
            return Ok(None);
        }

        src.advance(header_len);

        let masking_key = if masked {
            let key = src.split_to(4);
            Some([key[0], key[1], key[2], key[3]])
        } else {
            None
        };

        let mut payload = src.split_to(payload_len).to_vec();

        if let Some(mask) = masking_key {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }

        Ok(Some(WebsocketFrame {
            fin,
            opcode,
            payload,
        }))
    }
}

impl tokio_util::codec::Encoder<WebsocketFrame> for WebsocketCodec {
    type Error = WebsocketCodecError;

    fn encode(
        &mut self,
        item: WebsocketFrame,
        dst: &mut tokio_util::bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        let mut header = [0u8; 2];
        if item.fin {
            header[0] |= FIN_MASK;
        }
        header[0] |= u8::from(item.opcode);

        let mut mask_key = None;
        let mut payload = item.payload.clone();

        match self.endpoint_type {
            EndpointType::Client => {
                header[1] |= MASKBIT_MASK;
                let key: [u8; 4] = self.rng.random();
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= key[i % 4];
                }
                mask_key = Some(key);
            }
            EndpointType::Server => {}
        }

        // Encode length
        let len = payload.len();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "The lengths have been checked"
        )]
        match len {
            ..=125 => {
                header[1] |= len as u8;
                dst.extend_from_slice(&header);
            }
            126..=0xFFFF => {
                header[1] |= 126;
                dst.extend_from_slice(&header);
                dst.extend_from_slice(&(len as u16).to_be_bytes());
            }
            0x1_0000..=0x7FFF_FFFF_FFFF_FFFF => {
                header[1] |= 127;
                dst.extend_from_slice(&header);
                dst.extend_from_slice(&(len as u64).to_be_bytes());
            }
            _ => return Err(WebsocketCodecError::SizeError(len as u64)),
        }

        if let Some(key) = mask_key {
            dst.extend_from_slice(&key);
        }
        dst.extend_from_slice(&payload);

        Ok(())
    }
}
