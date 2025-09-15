//! Shared WebSocket connection types and logic for both client and server.

use std::collections::HashMap;

use http::{Request, Response, StatusCode};

use crate::codec::{self, Opcode};

// Trait alias for boxed stream type used in Connection
pub trait WebSocketStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> WebSocketStream for T {}

// Use ConnectionError from the errors module
use crate::errors::ConnectionError;

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
    /// Create a new builder with the required URI and max frame size.
    ///
    /// The host parameter in the URI is required and must be a valid domain name or IP address. The
    /// port is optional and defaults to 80 for "ws" scheme and 443 for "wss" scheme if not specified.
    /// The path is optional and defaults to "/" if not specified.
    ///
    /// Do not accept user input directly for the URI to avoid injection attacks.
    ///
    /// # Arguments
    /// * `uri`: The URI to connect to (host, port, path).
    /// * `max_frame_size`: The maximum frame size for incoming messages; larger frames will be split.
    pub fn builder(uri: http::Uri, max_frame_size: usize) -> ClientConnectionBuilder {
        ClientConnectionBuilder {
            uri,
            max_frame_size,
            sub_protocols: None,
            query_params: None,
            auth_header: None,
            cookies: None,
            origin: None,
        }
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
    ) -> Result<(), crate::errors::WebsocketCodecError> {
        // Import SinkExt only where used to avoid unused import warning
        if self.closed {
            return Err(crate::errors::WebsocketCodecError::ProtocolViolation(
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
            if let Some(opcode) = self.frag_opcode.take() {
                let payload = std::mem::take(&mut self.frag_buffer);
                if opcode == Opcode::TextFrame {
                    match std::str::from_utf8(&payload) {
                        Ok(s) => return Some(Ok(WebsocketMessage::Text(s.to_owned()))),
                        Err(_) => {
                            return Some(Err(ConnectionError::ProtocolViolation(
                                "Invalid UTF-8 in fragmented text message",
                            )));
                        }
                    }
                }
                return Some(Ok(WebsocketMessage::Binary(payload)));
            }
            // Defensive: unreachable, but return error if somehow None
            return Some(Err(ConnectionError::ProtocolViolation(
                "Continuation frame with missing opcode",
            )));
        }
        None
    }
}

async fn read_handshake_response<S>(stream: &mut S) -> Result<Response<()>, ConnectionError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|_| ConnectionError::ReadHandshakeFailed)?;
        if n == 0 {
            return Err(ConnectionError::ReadHandshakeFailed);
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err(ConnectionError::HandshakeResponseTooLarge);
        }
    }
    // Parse HTTP response using httparse
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut res = httparse::Response::new(&mut headers);
    let status = res
        .parse(&response)
        .map_err(|_| ConnectionError::ParseHandshakeFailed)?;
    if !status.is_complete() {
        return Err(ConnectionError::IncompleteHandshakeResponse);
    }
    let status_code = res.code.ok_or(ConnectionError::HandshakeMissingStatus)?;
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status_code).map_err(|_| ConnectionError::InvalidStatusCode)?);
    for h in res.headers.iter() {
        let name = http::header::HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|_| ConnectionError::InvalidHeaderName)?;
        let value = http::header::HeaderValue::from_bytes(h.value)
            .map_err(|_| ConnectionError::InvalidHeaderValue)?;
        builder = builder.header(name, value);
    }
    let response = builder
        .body(())
        .map_err(|_| ConnectionError::BuildHandshakeResponseFailed)?;
    Ok(response)
}

fn validate_handshake_response(response: &Response<()>, key: &str) -> Result<(), ConnectionError> {
    use base64::Engine as _;
    use sha1::{Digest, Sha1};
    // Check status code
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(ConnectionError::HandshakeMissingStatus);
    }
    // Check headers
    let upgrade = response
        .headers()
        .get("Upgrade")
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    if upgrade.as_deref() != Some("websocket") {
        return Err(ConnectionError::HandshakeMissingHeader("Upgrade"));
    }
    let connection = response
        .headers()
        .get("Connection")
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    if connection.as_deref() != Some("upgrade") {
        return Err(ConnectionError::HandshakeMissingHeader("Connection"));
    }
    // Validate Sec-WebSocket-Accept
    let accept = response
        .headers()
        .get("Sec-WebSocket-Accept")
        .and_then(|v| v.to_str().ok());
    let expected_accept = {
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
    };
    if accept != Some(expected_accept.as_str()) {
        return Err(ConnectionError::HandshakeInvalidAccept);
    }
    Ok(())
}

// Helper: Convert http::Request<()> to HTTP/1.1 string
fn request_to_http_string(req: &Request<()>) -> String {
    use std::fmt::Write as _;
    let mut s = format!(
        "{} {} HTTP/1.1\r\n",
        req.method(),
        req.uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
    );
    for (k, v) in req.headers() {
        let _ = write!(s, "{}: {}\r\n", k, v.to_str().unwrap_or(""));
    }
    s.push_str("\r\n");
    s
}

/// Builder for creating a WebSocket client connection with optional parameters.
pub struct ClientConnectionBuilder {
    uri: http::Uri,
    max_frame_size: usize,
    query_params: Option<HashMap<String, String>>,
    auth_header: Option<String>,
    cookies: Option<Vec<String>>,
    sub_protocols: Option<Vec<String>>,
    origin: Option<String>,
}

impl ClientConnectionBuilder {
    #[must_use]
    /// Add a sub-protocol to the WebSocket handshake request.
    /// The order of sub-protocols matters; the server will select the first one it supports.
    /// Do not use this method with untrusted input to avoid injection attacks.
    ///
    /// # Arguments
    /// * `protocol`: The sub-protocol to add.
    pub fn add_sub_protocol<S: Into<String>>(mut self, protocol: S) -> Self {
        self.sub_protocols
            .get_or_insert_with(Vec::new)
            .push(protocol.into());
        self
    }

    #[must_use]
    /// Add a single query parameter to be included in the WebSocket handshake request.
    ///
    /// Query parameters should not be URL-encoded; this method will handle encoding.
    /// Make sure that any parameters added are not from untrusted sources to avoid injection attacks.
    ///
    /// # Arguments
    /// * `key`: The query parameter key.
    /// * `value`: The query parameter value.
    pub fn add_query_param<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.query_params
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }

    #[must_use]
    /// Set the Authorization header for the WebSocket handshake request.
    ///
    /// It is the caller's responsibility to ensure the value is properly formatted (e.g., "Bearer <token>").
    /// Ensure that the value does not contain any characters that could break the HTTP header format.
    /// Also, be cautious about logging or exposing this value, as it may contain sensitive information, and do not
    /// use this method with untrusted input to avoid injection attacks.
    ///
    /// # Arguments
    /// * `value`: The value for the Authorization header.
    pub fn auth_header<S: AsRef<str>>(mut self, value: S) -> Self {
        self.auth_header = Some(value.as_ref().to_string());
        self
    }

    #[must_use]
    /// Add a single cookie to be included in the WebSocket handshake request.
    ///
    /// # Arguments
    /// * `cookie`: The cookie string to add.
    pub fn add_cookie<S: Into<String>>(mut self, cookie: S) -> Self {
        self.cookies
            .get_or_insert_with(Vec::new)
            .push(cookie.into());
        self
    }

    #[must_use]
    /// Set the Origin header for the WebSocket handshake request.
    ///
    /// # Arguments
    /// * `value`: The value for the Origin header.
    pub fn origin<S: AsRef<str>>(mut self, value: S) -> Self {
        self.origin = Some(value.as_ref().to_string());
        self
    }

    /// Build the handshake request with all options applied.
    fn build_request(&self) -> Result<(String, Request<()>), ConnectionError> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as base64;
        use rand::RngCore;
        use std::fmt::Write as _;

        let mut key_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        let key = base64.encode(key_bytes);

        // Build URI with query params if present
        let mut uri_string = self.uri.to_string();
        if let Some(params) = &self.query_params {
            let mut parts = self.uri.clone().into_parts();
            let mut query = String::new();
            for (i, (k, v)) in params.iter().enumerate() {
                if i > 0 {
                    query.push('&');
                }
                write!(
                    &mut query,
                    "{}={}",
                    urlencoding::encode(k),
                    urlencoding::encode(v)
                )
                .expect("writing query string");
            }
            let path = self.uri.path();
            let full = if query.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{query}")
            };
            parts.path_and_query = Some(
                full.parse()
                    .map_err(|_| ConnectionError::InvalidUri("invalid path/query"))?,
            );
            uri_string = http::Uri::from_parts(parts)
                .map_err(|_| ConnectionError::InvalidUri("invalid uri with query"))?
                .to_string();
        }

        let host = self
            .uri
            .host()
            .ok_or(ConnectionError::InvalidUri("missing host"))?;
        let mut req_builder = Request::builder()
            .method("GET")
            .uri(&uri_string)
            .header("Host", host)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", &key)
            .header("Sec-WebSocket-Version", "13");

        if let Some(auth) = &self.auth_header {
            req_builder = req_builder.header("Authorization", auth);
        }
        if let Some(cookies) = &self.cookies {
            let cookie_str = cookies.join("; ");
            req_builder = req_builder.header("Cookie", cookie_str);
        }
        if let Some(origin) = &self.origin {
            req_builder = req_builder.header("Origin", origin);
        }
        if let Some(sub_protocols) = &self.sub_protocols
            && !sub_protocols.is_empty()
        {
            let proto_str = sub_protocols.join(", ");
            req_builder = req_builder.header("Sec-WebSocket-Protocol", proto_str);
        }

        let req = req_builder
            .body(())
            .map_err(|_| ConnectionError::BuildHandshakeFailed)?;
        Ok((key, req))
    }

    /// Connect and return a WebSocket Connection using the configured options.
    ///
    /// # Errors
    /// Returns an error if the handshake fails or the connection cannot be established.
    pub async fn connect(self) -> Result<Connection, ConnectionError> {
        let scheme = self.uri.scheme_str();
        let (key, req) = self.build_request()?;
        match scheme {
            Some("ws") => connect_with_request(req, key, self.max_frame_size, false).await,
            Some("wss") => connect_with_request(req, key, self.max_frame_size, true).await,
            Some(s) => Err(ConnectionError::InvalidUri(match s {
                "http" => "http scheme is not supported for WebSocket",
                "https" => "https scheme is not supported for WebSocket",
                _ => "unsupported URI scheme for WebSocket",
            })),
            None => Err(ConnectionError::InvalidUri("missing URI scheme")),
        }
    }
}

/// Internal helper to connect using a pre-built request and key.
async fn connect_with_request(
    req: Request<()>,
    key: String,
    max_frame_size: usize,
    secure: bool,
) -> Result<Connection, ConnectionError> {
    use tokio::io::AsyncWriteExt;
    if secure {
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};
        let uri = req.uri();
        let host = uri
            .host()
            .ok_or(ConnectionError::InvalidUri("missing host"))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let addr = format!("{host}:{port}");
        let tcp_stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|_| ConnectionError::ConnectFailed)?;
        let root_store = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name =
            ServerName::try_from(host).map_err(|_| ConnectionError::InvalidDnsName)?;
        let mut stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
        let req_str = request_to_http_string(&req);
        stream
            .write_all(req_str.as_bytes())
            .await
            .map_err(|_| ConnectionError::WriteHandshakeFailed)?;
        let response = read_handshake_response(&mut stream).await?;
        validate_handshake_response(&response, &key)?;
        let codec =
            crate::codec::WebsocketCodec::new(crate::codec::EndpointType::Client, max_frame_size);
        Ok(Connection {
            framed: tokio_util::codec::Framed::new(
                Box::new(stream) as Box<dyn crate::connection::WebSocketStream + Send>,
                codec,
            ),
            max_frame_size,
            closed: false,
            last_ping: None,
            frag_opcode: None,
            frag_buffer: Vec::new(),
        })
    } else {
        let uri = req.uri();
        let mut stream = tokio::net::TcpStream::connect((
            uri.host()
                .ok_or(ConnectionError::InvalidUri("missing host"))?,
            uri.port_u16().unwrap_or(80),
        ))
        .await
        .map_err(|_| ConnectionError::ConnectFailed)?;
        let req_str = request_to_http_string(&req);
        stream
            .write_all(req_str.as_bytes())
            .await
            .map_err(|_| ConnectionError::WriteHandshakeFailed)?;
        let response = read_handshake_response(&mut stream).await?;
        validate_handshake_response(&response, &key)?;
        let codec =
            crate::codec::WebsocketCodec::new(crate::codec::EndpointType::Client, max_frame_size);
        let framed = tokio_util::codec::Framed::new(
            Box::new(stream) as Box<dyn crate::connection::WebSocketStream + Send>,
            codec,
        );
        Ok(Connection {
            framed,
            max_frame_size,
            closed: false,
            last_ping: None,
            frag_opcode: None,
            frag_buffer: Vec::new(),
        })
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
