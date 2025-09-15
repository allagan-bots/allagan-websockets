//! Error types for the allagan-websocket crate.

use thiserror::Error;

/// Errors produced by the WebSocket codec (framing, protocol, IO, etc).

#[derive(Debug, Error)]
pub enum WebsocketCodecError {
    /// The opcode in the WebSocket frame is not recognized.
    #[error("Unknown Opcode {0}")]
    UnknownOpcode(u8),
    /// An underlying I/O error occurred during WebSocket processing.
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    /// The WebSocket frame or message is too large.
    #[error("Packet too big: {0} bytes")]
    SizeError(u64),
    /// The WebSocket protocol was violated in some way.
    #[error("Protocol violation: {0}")]
    ProtocolViolation(&'static str),
}

impl Clone for WebsocketCodecError {
    fn clone(&self) -> Self {
        match self {
            WebsocketCodecError::UnknownOpcode(op) => WebsocketCodecError::UnknownOpcode(*op),
            WebsocketCodecError::IOError(e) => {
                WebsocketCodecError::IOError(std::io::Error::new(e.kind(), e.to_string()))
            }
            WebsocketCodecError::SizeError(size) => WebsocketCodecError::SizeError(*size),
            WebsocketCodecError::ProtocolViolation(msg) => {
                WebsocketCodecError::ProtocolViolation(msg)
            }
        }
    }
}

/// Errors produced by the WebSocket connection and handshake logic.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// The WebSocket protocol was violated in some way.
    #[error("WebSocket protocol violation: {0}")]
    ProtocolViolation(&'static str),
    /// The WebSocket connection has been closed.
    #[error("WebSocket closed")]
    Closed,
    /// An error occurred in the WebSocket codec.
    #[error("Codec error: {0}")]
    Codec(#[from] WebsocketCodecError),
    /// The provided URI is invalid.
    #[error("Invalid URI: {0}")]
    InvalidUri(&'static str),
    /// Failed to connect to the server.
    #[error("Failed to connect to server")]
    ConnectFailed,
    /// Failed to write the handshake request to the server.
    #[error("Failed to write handshake request")]
    WriteHandshakeFailed,
    /// Failed to read the handshake response from the server.
    #[error("Failed to read handshake response")]
    ReadHandshakeFailed,
    /// The handshake response from the server was too large.
    #[error("Handshake response too large")]
    HandshakeResponseTooLarge,
    /// The handshake response was missing or had an invalid status code.
    #[error("Handshake failed: missing or invalid status code")]
    HandshakeMissingStatus,
    /// The handshake response was missing or had an invalid header.
    #[error("Handshake failed: missing or invalid header: {0}")]
    HandshakeMissingHeader(&'static str),
    /// The handshake response had an invalid Sec-WebSocket-Accept value.
    #[error("Handshake failed: invalid Sec-WebSocket-Accept value")]
    HandshakeInvalidAccept,
    /// The TLS handshake failed.
    #[error("TLS handshake failed")]
    TlsHandshakeFailed,
    /// The DNS name for TLS was invalid.
    #[error("Invalid DNS name for TLS")]
    InvalidDnsName,
    /// Failed to build the handshake request.
    #[error("Failed to build handshake request")]
    BuildHandshakeFailed,
    /// Failed to build the handshake response.
    #[error("Failed to build handshake response")]
    BuildHandshakeResponseFailed,
    /// Failed to parse the handshake response.
    #[error("Failed to parse handshake response")]
    ParseHandshakeFailed,
    /// The handshake response was incomplete.
    #[error("Incomplete handshake response")]
    IncompleteHandshakeResponse,
    /// The handshake response had an invalid header name.
    #[error("Invalid header name")]
    InvalidHeaderName,
    /// The handshake response had an invalid header value.
    #[error("Invalid header value")]
    InvalidHeaderValue,
    /// The handshake response had an invalid status code.
    #[error("Invalid status code")]
    InvalidStatusCode,
}
