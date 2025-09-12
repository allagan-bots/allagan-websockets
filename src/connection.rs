//! WebSocket connection handling module.
//! This module provides a `Connection` type that manages a WebSocket connection,
//! handling framing, control frames, and message fragmentation according to RFC 6455.

/// Perform a client-side WebSocket handshake over a secure (TLS) connection.
/// # Arguments
/// * `stream`: The underlying stream to use for the connection (e.g., a TCP stream).
/// * `host`: The hostname of the server to connect to (used in the handshake and SNI).
/// * `path`: The request path for the WebSocket handshake (usually "/").
/// * `max_frame_size`: The maximum frame size for incoming messages; larger frames will be split.
/// * `tls_config`: The Rustls client config to use for TLS.
///
/// # Errors
/// Returns an error if the TLS or WebSocket handshake fails.
pub async fn new_secure_client<T>(
    stream: T,
    host: &str,
    path: &str,
    max_frame_size: usize,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
) -> Result<Connection<tokio_rustls::client::TlsStream<T>>, ConnectionError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let tls_config = tls_config.unwrap_or(std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned()
                    .collect::<rustls::RootCertStore>(),
            )
            .with_no_client_auth(),
    ));
    let connector = TlsConnector::from(tls_config);
    let host_owned: String = host.to_owned();
    let server_name = ServerName::try_from(host_owned)
        .map_err(|_| ConnectionError::ProtocolViolation("Invalid SNI/host for TLS"))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|_| ConnectionError::ProtocolViolation("TLS handshake failed"))?;
    Connection::new_insecure_client(tls_stream, host, path, max_frame_size).await
}

/// Accept a server-side WebSocket handshake over a secure (TLS) connection.
///
/// # Arguments
/// * `stream`: The underlying stream to use for the connection (e.g., a TCP stream).
/// * `max_frame_size`: The maximum frame size for incoming messages; larger frames will be split.
/// * `tls_config`: The Rustls server config to use for TLS.
///
/// # Errors
/// Returns an error if the TLS or WebSocket handshake fails.
pub async fn new_secure_server<T>(
    stream: T,
    max_frame_size: usize,
    tls_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<Connection<tokio_rustls::server::TlsStream<T>>, ConnectionError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio_rustls::TlsAcceptor;
    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|_| ConnectionError::ProtocolViolation("TLS handshake failed"))?;
    Connection::new_insecure_server(tls_stream, max_frame_size).await
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("WebSocket protocol violation: {0}")]
    ProtocolViolation(&'static str),
    #[error("WebSocket closed")]
    Closed,
    #[error("Codec error: {0}")]
    Codec(#[from] crate::codec::WebsocketCodecError),
}

use crate::codec::{self, Opcode};

/// A message returned to end-users from a WebSocket connection.
#[derive(Debug, Clone, PartialEq)]
pub enum WebsocketMessage {
    Text(String),
    Binary(Vec<u8>),
    Close(Option<Vec<u8>>),
    Pong(Vec<u8>),
    Ping(Vec<u8>),
}

/// Handler for a WebSocket connection, generic over [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`].
pub struct Connection<T> {
    framed: tokio_util::codec::Framed<T, codec::WebsocketCodec>,
    max_frame_size: usize,
    closed: bool,
    last_ping: Option<Vec<u8>>,
    frag_opcode: Option<codec::Opcode>,
    frag_buffer: Vec<u8>,
}

impl<T> Connection<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Perform a client-side WebSocket handshake and return a new insecure (non-TLS) client connection.
    /// Create a new insecure (non-TLS) WebSocket client connection.
    ///
    /// # Arguments
    ///
    /// * `stream`: The underlying stream to use for the connection (e.g., a TCP stream).
    /// * `host`: The hostname of the server to connect to (used in the handshake).
    /// * `path`: The request path for the WebSocket handshake (usually "/").
    /// * `max_frame_size`: The maximum frame size for incoming messages; larger frames will be split.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake fails or the connection cannot be established.
    pub async fn new_insecure_client(
        mut stream: T,
        host: &str,
        path: &str,
        max_frame_size: usize,
    ) -> Result<Self, ConnectionError> {
        use base64::engine::general_purpose::STANDARD as base64;
        use base64::Engine;
        use rand::RngCore;
        use sha1::{Digest, Sha1};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Generate a random key
        let mut key_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        let key = base64.encode(key_bytes);

        // Write handshake request
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|_| ConnectionError::ProtocolViolation("Failed to write handshake request"))?;

        // Read handshake response
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.map_err(|_| {
                ConnectionError::ProtocolViolation("Failed to read handshake response")
            })?;
            if n == 0 {
                return Err(ConnectionError::ProtocolViolation(
                    "Connection closed during handshake",
                ));
            }
            response.extend_from_slice(&buf[..n]);
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if response.len() > 8192 {
                return Err(ConnectionError::ProtocolViolation(
                    "Handshake response too large",
                ));
            }
        }
        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 101") {
            return Err(ConnectionError::ProtocolViolation(
                "Handshake failed: missing 101 status",
            ));
        }
        if !response_str
            .to_ascii_lowercase()
            .contains("upgrade: websocket")
        {
            return Err(ConnectionError::ProtocolViolation(
                "Handshake failed: missing upgrade header",
            ));
        }
        if !response_str
            .to_ascii_lowercase()
            .contains("connection: upgrade")
        {
            return Err(ConnectionError::ProtocolViolation(
                "Handshake failed: missing connection header",
            ));
        }
        // Validate Sec-WebSocket-Accept
        let accept_line = response_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-accept:"));
        let expected_accept = {
            let mut sha1 = Sha1::new();
            sha1.update(key.as_bytes());
            sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            base64.encode(sha1.finalize())
        };
        match accept_line {
            Some(line) => {
                let actual = line.split(':').nth(1).map(str::trim);
                if actual != Some(expected_accept.as_str()) {
                    return Err(ConnectionError::ProtocolViolation(
                        "Invalid Sec-WebSocket-Accept value",
                    ));
                }
            }
            None => {
                return Err(ConnectionError::ProtocolViolation(
                    "Missing Sec-WebSocket-Accept header",
                ))
            }
        }

        let codec = codec::WebsocketCodec::new(codec::EndpointType::Client, max_frame_size);
        Ok(Self {
            framed: tokio_util::codec::Framed::new(stream, codec),
            max_frame_size,
            closed: false,
            last_ping: None,
            frag_opcode: None,
            frag_buffer: Vec::new(),
        })
    }

    /// Accept a server-side WebSocket handshake and return a new insecure (non-TLS) server connection.
    ///
    /// # Arguments
    ///
    /// * `stream`: The underlying stream to use for the connection (e.g., a TCP stream).
    /// * `max_frame_size`: The maximum frame size for incoming messages; larger frames will be split.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake fails or the connection cannot be established.
    pub async fn new_insecure_server(
        mut stream: T,
        max_frame_size: usize,
    ) -> Result<Self, ConnectionError> {
        use base64::engine::general_purpose::STANDARD as base64;
        use base64::Engine;
        use sha1::{Digest, Sha1};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Read handshake request
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.map_err(|_| {
                ConnectionError::ProtocolViolation("Failed to read handshake request")
            })?;
            if n == 0 {
                return Err(ConnectionError::ProtocolViolation(
                    "Connection closed during handshake",
                ));
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if request.len() > 8192 {
                return Err(ConnectionError::ProtocolViolation(
                    "Handshake request too large",
                ));
            }
        }
        let request_str = String::from_utf8_lossy(&request);
        if !request_str.starts_with("GET ") {
            return Err(ConnectionError::ProtocolViolation(
                "Handshake request must start with GET",
            ));
        }
        if !request_str
            .to_ascii_lowercase()
            .contains("upgrade: websocket")
        {
            return Err(ConnectionError::ProtocolViolation(
                "Handshake failed: missing upgrade header",
            ));
        }
        if !request_str
            .to_ascii_lowercase()
            .contains("connection: upgrade")
        {
            return Err(ConnectionError::ProtocolViolation(
                "Handshake failed: missing connection header",
            ));
        }
        // Extract Sec-WebSocket-Key
        let key_line = request_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"));
        let key =
            match key_line {
                Some(line) => line.split(':').nth(1).map(str::trim).ok_or(
                    ConnectionError::ProtocolViolation("Malformed Sec-WebSocket-Key header"),
                )?,
                None => {
                    return Err(ConnectionError::ProtocolViolation(
                        "Missing Sec-WebSocket-Key header",
                    ))
                }
            };
        // Compute accept value
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = base64.encode(sha1.finalize());
        // Write handshake response
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.map_err(|_| {
            ConnectionError::ProtocolViolation("Failed to write handshake response")
        })?;

        let codec = codec::WebsocketCodec::new(codec::EndpointType::Server, max_frame_size);
        Ok(Self {
            framed: tokio_util::codec::Framed::new(stream, codec),
            max_frame_size,
            closed: false,
            last_ping: None,
            frag_opcode: None,
            frag_buffer: Vec::new(),
        })
    }

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
        loop {
            let frame = self.framed.next().await?;
            match &frame {
                Ok(f) => match f.opcode {
                    Opcode::Ping | Opcode::Pong | Opcode::ConnectionClose => {
                        if f.payload.len() > 125 {
                            return Some(Err(ConnectionError::ProtocolViolation(
                                "Control frame payload exceeds 125 bytes",
                            )));
                        }
                        match f.opcode {
                            Opcode::Ping => {
                                let _ = self.send_data(&f.payload, Opcode::Pong).await;
                                return Some(Ok(WebsocketMessage::Ping(f.payload.clone())));
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
                                return Some(Ok(WebsocketMessage::Pong(f.payload.clone())));
                            }
                            Opcode::ConnectionClose => {
                                let _ = self.send_data(&f.payload, Opcode::ConnectionClose).await;
                                self.closed = true;
                                let reason = if f.payload.is_empty() {
                                    None
                                } else {
                                    Some(f.payload.clone())
                                };
                                return Some(Ok(WebsocketMessage::Close(reason)));
                            }
                            _ => unreachable!(),
                        }
                    }
                    Opcode::TextFrame | Opcode::BinaryFrame => {
                        if self.frag_opcode.is_some() {
                            return Some(Err(ConnectionError::ProtocolViolation(
                                "New data frame started before previous fragmented message completed",
                            )));
                        }
                        if f.fin {
                            if f.opcode == Opcode::TextFrame {
                                match std::str::from_utf8(&f.payload) {
                                    Ok(s) => return Some(Ok(WebsocketMessage::Text(s.to_owned()))),
                                    Err(_) => {
                                        return Some(Err(ConnectionError::ProtocolViolation(
                                            "Invalid UTF-8 in text frame",
                                        )))
                                    }
                                }
                            }
                            return Some(Ok(WebsocketMessage::Binary(f.payload.clone())));
                        }
                        self.frag_opcode = Some(f.opcode);
                        self.frag_buffer.clear();
                        self.frag_buffer.extend_from_slice(&f.payload);
                    }
                    Opcode::ContinuationFrame => {
                        if self.frag_opcode.is_none() {
                            return Some(Err(ConnectionError::ProtocolViolation(
                                "Continuation frame without initial data frame",
                            )));
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
                    }
                },
                Err(e) => return Some(Err(ConnectionError::Codec((*e).clone()))),
            }
        }
    }
}
