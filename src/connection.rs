//! Shared WebSocket connection types and logic for both client and server.

pub(crate) mod client;
pub(crate) mod server;

use crate::codec::{self, Opcode};

// Trait alias for boxed stream type used in Connection
pub trait WebSocketStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> WebSocketStream for T {}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("WebSocket protocol violation: {0}")]
    ProtocolViolation(&'static str),
    #[error("WebSocket closed")]
    Closed,
    #[error("Codec error: {0}")]
    Codec(#[from] crate::codec::WebsocketCodecError),
    #[error("Invalid URI: {0}")]
    InvalidUri(&'static str),
    #[error("Failed to connect to server")]
    ConnectFailed,
    #[error("Failed to write handshake request")]
    WriteHandshakeFailed,
    #[error("Failed to read handshake response")]
    ReadHandshakeFailed,
    #[error("Handshake response too large")]
    HandshakeResponseTooLarge,
    #[error("Handshake failed: missing or invalid status code")]
    HandshakeMissingStatus,
    #[error("Handshake failed: missing or invalid header: {0}")]
    HandshakeMissingHeader(&'static str),
    #[error("Handshake failed: invalid Sec-WebSocket-Accept value")]
    HandshakeInvalidAccept,
    #[error("TLS handshake failed")]
    TlsHandshakeFailed,
    #[error("Invalid DNS name for TLS")]
    InvalidDnsName,
    #[error("Failed to build handshake request")]
    BuildHandshakeFailed,
    #[error("Failed to build handshake response")]
    BuildHandshakeResponseFailed,
    #[error("Failed to parse handshake response")]
    ParseHandshakeFailed,
    #[error("Incomplete handshake response")]
    IncompleteHandshakeResponse,
    #[error("Invalid header name")]
    InvalidHeaderName,
    #[error("Invalid header value")]
    InvalidHeaderValue,
    #[error("Invalid status code")]
    InvalidStatusCode,
}

/// A message returned to end-users from a WebSocket connection.
#[derive(Debug, Clone, PartialEq)]
pub enum WebsocketMessage {
    /// A string of text
    Text(String),
    /// A block of binary data
    Binary(Vec<u8>),
    /// A close operation
    Close(Option<(CloseReason, String)>),
    /// A ping
    Pong(Vec<u8>),
    /// Response to ping
    Ping(Vec<u8>),
}

/// A websocket connection
pub struct Connection {
    pub(crate) framed:
        tokio_util::codec::Framed<Box<dyn WebSocketStream + Send>, codec::WebsocketCodec>,
    pub(crate) max_frame_size: usize,
    pub(crate) closed: bool,
    pub(crate) last_ping: Option<Vec<u8>>,
    pub(crate) frag_opcode: Option<codec::Opcode>,
    pub(crate) frag_buffer: Vec<u8>,
}

impl Connection {
    /// Send a text message, splitting into frames if needed.
    /// # Errors
    /// Returns an error if the connection is closed or sending fails.
    pub async fn send_text(&mut self, text: &str) -> Result<(), ConnectionError> {
        if self.closed {
            return Err(ConnectionError::Closed);
        }
        let bytes = text.as_bytes();
        self.send_data(bytes, codec::Opcode::TextFrame)
            .await
            .map_err(ConnectionError::from)
    }

    /// Send a binary message, splitting into frames if needed.
    /// # Errors
    /// Returns an error if the connection is closed or sending fails.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        if self.closed {
            return Err(ConnectionError::Closed);
        }
        self.send_data(data, codec::Opcode::BinaryFrame)
            .await
            .map_err(ConnectionError::from)
    }

    /// Send a ping frame and store the payload for pong validation.
    /// # Errors
    /// Returns an error if the connection is closed or sending fails.
    pub async fn send_ping(&mut self, payload: Vec<u8>) -> Result<(), ConnectionError> {
        if self.closed {
            return Err(ConnectionError::Closed);
        }
        self.last_ping = Some(payload.clone());
        self.send_data(&payload, codec::Opcode::Ping)
            .await
            .map_err(ConnectionError::from)
    }

    async fn send_data(
        &mut self,
        data: &[u8],
        opcode: codec::Opcode,
    ) -> Result<(), crate::codec::WebsocketCodecError> {
        // Import SinkExt only where used to avoid unused import warning
        if self.closed {
            return Err(crate::codec::WebsocketCodecError::ProtocolViolation(
                "Connection closed",
            ));
        }
        let mut offset = 0;
        let total = data.len();
        let max = self.max_frame_size;
        let mut first = true;
        while offset < total {
            let end = usize::min(offset + max, total);
            let fin = end == total;
            let frame = codec::WebsocketFrame {
                fin,
                opcode: if first {
                    opcode
                } else {
                    codec::Opcode::ContinuationFrame
                },
                payload: data[offset..end].to_vec(),
            };
            futures_util::SinkExt::send(&mut self.framed, frame).await?;
            offset = end;
            first = false;
        }
        Ok(())
    }

    /// Poll for the next application frame, handling control frames internally.
    /// Responds to ping, pong, and close frames as per RFC 6455.
    /// # Panics
    /// Panics if internal state has gone absolutely bonkers, which should never happen.
    pub async fn next_message(&mut self) -> Option<Result<WebsocketMessage, ConnectionError>> {
        use futures_util::StreamExt;

        let frame = self.framed.next().await?;
        match &frame {
            Ok(f) => match f.opcode {
                Opcode::Ping | Opcode::Pong | Opcode::ConnectionClose => {
                    return self.handle_control_frame(f).await;
                }
                Opcode::TextFrame | Opcode::BinaryFrame => self.handle_data_frame(f),
                Opcode::ContinuationFrame => self.handle_continuation_frame(f),
            },
            Err(e) => Some(Err(ConnectionError::Codec((*e).clone()))),
        }
    }

    async fn handle_control_frame(
        &mut self,
        f: &crate::codec::WebsocketFrame,
    ) -> Option<Result<WebsocketMessage, ConnectionError>> {
        if f.payload.len() > 125 {
            return Some(Err(ConnectionError::ProtocolViolation(
                "Control frame payload exceeds 125 bytes",
            )));
        }
        if !f.fin {
            return Some(Err(ConnectionError::ProtocolViolation(
                "Control frames must not be fragmented",
            )));
        }
        match f.opcode {
            Opcode::Ping => {
                let _ = self.send_data(&f.payload, Opcode::Pong).await;
                Some(Ok(WebsocketMessage::Ping(f.payload.clone())))
            }
            Opcode::Pong => {
                if let Some(last) = &self.last_ping {
                    if &f.payload != last {
                        return Some(Err(ConnectionError::ProtocolViolation(
                            "Pong payload does not match last ping",
                        )));
                    }
                } else if !f.payload.is_empty() {
                    return Some(Err(ConnectionError::ProtocolViolation(
                        "Unexpected pong with payload",
                    )));
                }
                self.last_ping = None;
                Some(Ok(WebsocketMessage::Pong(f.payload.clone())))
            }
            Opcode::ConnectionClose => {
                let _ = self.send_data(&f.payload, Opcode::ConnectionClose).await;
                self.closed = true;
                let close_info = if f.payload.is_empty() {
                    None
                } else if f.payload.len() >= 2 {
                    let code = u16::from_be_bytes([f.payload[0], f.payload[1]]);
                    let reason = if f.payload.len() > 2 {
                        match std::str::from_utf8(&f.payload[2..]) {
                            Ok(s) => s.to_owned(),
                            Err(_) => String::from("Invalid UTF-8 in close reason"),
                        }
                    } else {
                        String::new()
                    };
                    match CloseReason::try_from(code) {
                        Ok(r) => Some((r, reason)),
                        Err(()) => Some((CloseReason::NormalClosure, reason)),
                    }
                } else {
                    None
                };
                Some(Ok(WebsocketMessage::Close(close_info)))
            }
            _ => unreachable!(),
        }
    }

    /// Send a close frame with an optional reason code.
    /// If a reason is provided, the reason string will be the Display of the [`CloseReason`].
    /// # Errors
    /// Returns an error if the connection is closed or sending fails.
    pub async fn send_close(&mut self, reason: Option<CloseReason>) -> Result<(), ConnectionError> {
        if self.closed {
            return Err(ConnectionError::Closed);
        }
        let payload = if let Some(r) = reason {
            let mut data = Vec::with_capacity(2 + 64); // 2 bytes for code, rest for string
            data.extend_from_slice(&u16::from(r).to_be_bytes());
            let reason_str = r.to_string();
            data.extend_from_slice(reason_str.as_bytes());
            data
        } else {
            Vec::new()
        };
        self.send_data(&payload, crate::codec::Opcode::ConnectionClose)
            .await?;
        self.closed = true;
        Ok(())
    }

    fn handle_data_frame(
        &mut self,
        f: &crate::codec::WebsocketFrame,
    ) -> Option<Result<WebsocketMessage, ConnectionError>> {
        if self.frag_opcode.is_some() {
            return Some(Err(ConnectionError::ProtocolViolation(
                "New data frame started before previous fragmented message completed",
            )));
        }
        if f.fin {
            if f.opcode == Opcode::TextFrame {
                if let Ok(s) = std::str::from_utf8(&f.payload) {
                    return Some(Ok(WebsocketMessage::Text(s.to_owned())));
                }
                return Some(Err(ConnectionError::ProtocolViolation(
                    "Invalid UTF-8 in text frame",
                )));
            }
            return Some(Ok(WebsocketMessage::Binary(f.payload.clone())));
        }
        self.frag_opcode = Some(f.opcode);
        self.frag_buffer.clear();
        self.frag_buffer.extend_from_slice(&f.payload);
        None
    }

    fn handle_continuation_frame(
        &mut self,
        f: &crate::codec::WebsocketFrame,
    ) -> Option<Result<WebsocketMessage, ConnectionError>> {
        if self.frag_opcode.is_none() {
            return Some(Err(ConnectionError::ProtocolViolation(
                "Continuation frame without initial data frame",
            )));
        }
        // If this is a fragmented text message, check that the new fragment is valid UTF-8 up to this point
        if self.frag_opcode == Some(Opcode::TextFrame) {
            // Check that the new fragment is valid UTF-8 (not the whole buffer, just the new payload)
            if !f.payload.is_empty() && std::str::from_utf8(&f.payload).is_err() {
                return Some(Err(ConnectionError::ProtocolViolation(
                    "Invalid UTF-8 in continuation frame of fragmented text message",
                )));
            }
        }
        self.frag_buffer.extend_from_slice(&f.payload);
        if f.fin {
            #[allow(clippy::expect_used, reason = "Checked is_some above")]
            let opcode = self.frag_opcode.take().expect("Checked is_some above");
            let payload = std::mem::take(&mut self.frag_buffer);
            if opcode == Opcode::TextFrame {
                match std::str::from_utf8(&payload) {
                    Ok(s) => return Some(Ok(WebsocketMessage::Text(s.to_owned()))),
                    Err(_) => {
                        return Some(Err(ConnectionError::ProtocolViolation(
                            "Invalid UTF-8 in fragmented text message",
                        )))
                    }
                }
            }
            return Some(Ok(WebsocketMessage::Binary(payload)));
        }
        None
    }
}

// WebSocket close reason codes as defined in RFC 6455 §7.4.1
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// 1000: Normal closure
    NormalClosure = 1000,
    /// 1001: Endpoint is going away
    GoingAway = 1001,
    /// 1002: Protocol error
    ProtocolError = 1002,
    /// 1003: Unsupported data
    UnsupportedData = 1003,
    /// 1005: No status received (reserved, not to be sent)
    NoStatusReceived = 1005,
    /// 1006: Abnormal closure (reserved, not to be sent)
    AbnormalClosure = 1006,
    /// 1007: Invalid payload data
    InvalidPayloadData = 1007,
    /// 1008: Policy violation
    PolicyViolation = 1008,
    /// 1009: Message too big
    MessageTooBig = 1009,
    /// 1010: Mandatory extension (client only)
    MandatoryExtension = 1010,
    /// 1011: Internal server error
    InternalServerError = 1011,
    /// 1012: Service restart (optional, not in RFC 6455, but in IANA registry)
    ServiceRestart = 1012,
    /// 1013: Try again later (optional, not in RFC 6455, but in IANA registry)
    TryAgainLater = 1013,
    /// 1014: Bad gateway (optional, not in RFC 6455, but in IANA registry)
    BadGateway = 1014,
    /// 1015: TLS handshake failure (reserved, not to be sent)
    TlsHandshake = 1015,
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseReason::NormalClosure => write!(f, "Normal closure"),
            CloseReason::GoingAway => write!(f, "Endpoint is going away"),
            CloseReason::ProtocolError => write!(f, "Protocol error"),
            CloseReason::UnsupportedData => write!(f, "Unsupported data"),
            CloseReason::NoStatusReceived => write!(f, "No status received"),
            CloseReason::AbnormalClosure => write!(f, "Abnormal closure"),
            CloseReason::InvalidPayloadData => write!(f, "Invalid payload data"),
            CloseReason::PolicyViolation => write!(f, "Policy violation"),
            CloseReason::MessageTooBig => write!(f, "Message too big"),
            CloseReason::MandatoryExtension => write!(f, "Mandatory extension"),
            CloseReason::InternalServerError => write!(f, "Internal server error"),
            CloseReason::ServiceRestart => write!(f, "Service restart"),
            CloseReason::TryAgainLater => write!(f, "Try again later"),
            CloseReason::BadGateway => write!(f, "Bad gateway"),
            CloseReason::TlsHandshake => write!(f, "TLS handshake failure"),
        }
    }
}

impl TryFrom<u16> for CloseReason {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1000 => Ok(CloseReason::NormalClosure),
            1001 => Ok(CloseReason::GoingAway),
            1002 => Ok(CloseReason::ProtocolError),
            1003 => Ok(CloseReason::UnsupportedData),
            1005 => Ok(CloseReason::NoStatusReceived),
            1006 => Ok(CloseReason::AbnormalClosure),
            1007 => Ok(CloseReason::InvalidPayloadData),
            1008 => Ok(CloseReason::PolicyViolation),
            1009 => Ok(CloseReason::MessageTooBig),
            1010 => Ok(CloseReason::MandatoryExtension),
            1011 => Ok(CloseReason::InternalServerError),
            1012 => Ok(CloseReason::ServiceRestart),
            1013 => Ok(CloseReason::TryAgainLater),
            1014 => Ok(CloseReason::BadGateway),
            1015 => Ok(CloseReason::TlsHandshake),
            _ => Err(()),
        }
    }
}

impl TryFrom<[u8; 2]> for CloseReason {
    type Error = ();
    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        let code = u16::from_be_bytes(value);
        CloseReason::try_from(code)
    }
}

impl TryFrom<&[u8]> for CloseReason {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(());
        }
        let code = u16::from_be_bytes([value[0], value[1]]);
        CloseReason::try_from(code)
    }
}

impl From<CloseReason> for u16 {
    fn from(value: CloseReason) -> Self {
        value as u16
    }
}

impl From<CloseReason> for [u8; 2] {
    fn from(value: CloseReason) -> Self {
        (value as u16).to_be_bytes()
    }
}
