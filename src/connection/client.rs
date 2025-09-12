use crate::connection::{Connection, ConnectionError};
use http::{Request, Response, StatusCode};
use std::collections::HashMap;

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
            query_params: None,
            auth_header: None,
            cookies: None,
            origin: None,
        }
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
    origin: Option<String>,
}

impl ClientConnectionBuilder {
    #[must_use]
    /// Set query parameters to be included in the WebSocket handshake request.
    ///
    /// # Arguments
    /// * `params`: A map of query parameter key-value pairs.
    pub fn query_params<T>(mut self, params: T) -> Self
    where
        T: Into<HashMap<String, String>>,
    {
        self.query_params = Some(params.into());
        self
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic")]
    /// Add a single query parameter to be included in the WebSocket handshake request.
    ///
    /// Query parameters should not be URL-encoded; this method will handle encoding.
    /// Make sure that any parameters added are not from untrusted sources to avoid injection attacks.
    ///
    /// # Arguments
    /// * `key`: The query parameter key.
    /// * `value`: The query parameter value.
    pub fn add_query_param<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        if self.query_params.is_none() {
            self.query_params = Some(HashMap::new());
        }
        self.query_params
            .as_mut()
            .expect("query_params should be initialized")
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
    /// Set cookies to be included in the WebSocket handshake request.
    ///
    /// Ensure that the cookie strings do not contain any characters that could break the HTTP header format.
    /// It is the caller's responsibility to ensure the cookies are properly formatted. Be cautious about logging or exposing
    /// these values, as they may contain sensitive information, and do not use this method with untrusted input to avoid injection attacks.
    ///
    /// # Arguments
    /// * `cookies`: An iterable of cookie strings.
    pub fn cookies<T>(mut self, cookies: T) -> Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
    {
        self.cookies = Some(cookies.into_iter().map(Into::into).collect());
        self
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic")]
    /// Add a single cookie to be included in the WebSocket handshake request.
    ///
    /// # Arguments
    /// * `cookie`: The cookie string to add.
    pub fn add_cookie<S: Into<String>>(&mut self, cookie: S) -> &mut Self {
        if self.cookies.is_none() {
            self.cookies = Some(Vec::new());
        }
        self.cookies
            .as_mut()
            .expect("cookies should be initialized")
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
        use base64::engine::general_purpose::STANDARD as base64;
        use base64::Engine as _;
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
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};
        use tokio_rustls::TlsConnector;
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
