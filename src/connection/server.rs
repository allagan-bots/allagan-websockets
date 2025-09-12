use crate::connection::{Connection, ConnectionError};

impl Connection {
    /// Accept a server-side WebSocket handshake and return a new insecure (non-TLS) server connection.
    ///
    /// # Arguments
    ///
    /// * `port`: The port to listen on (defaults to 80 if None)
    /// * `max_frame_size`: The maximum frame size for incoming messages; larger frames will be split.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake fails or the connection cannot be established.
    pub async fn new_insecure_server(
        port: Option<u16>,
        max_frame_size: usize,
    ) -> Result<Connection, ConnectionError> {
        use base64::engine::general_purpose::STANDARD as base64;
        use base64::Engine;
        use sha1::{Digest, Sha1};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let port = port.unwrap_or(80);
        let addr = format!("0.0.0.0:{port}");
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|_| ConnectionError::ConnectFailed)?;
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|_| ConnectionError::ConnectFailed)?;

        // Read handshake request
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|_| ConnectionError::ReadHandshakeFailed)?;
            if n == 0 {
                return Err(ConnectionError::ReadHandshakeFailed);
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if request.len() > 8192 {
                return Err(ConnectionError::HandshakeResponseTooLarge);
            }
        }
        let request_str = String::from_utf8_lossy(&request);
        if !request_str.starts_with("GET ") {
            return Err(ConnectionError::HandshakeMissingStatus);
        }
        if !request_str
            .to_ascii_lowercase()
            .contains("upgrade: websocket")
        {
            return Err(ConnectionError::HandshakeMissingHeader("Upgrade"));
        }
        if !request_str
            .to_ascii_lowercase()
            .contains("connection: upgrade")
        {
            return Err(ConnectionError::HandshakeMissingHeader("Connection"));
        }
        // Extract Sec-WebSocket-Key
        let key_line = request_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"));
        let key = match key_line {
            Some(line) => line
                .split(':')
                .nth(1)
                .map(str::trim)
                .ok_or(ConnectionError::HandshakeMissingHeader("Sec-WebSocket-Key"))?,
            None => return Err(ConnectionError::HandshakeMissingHeader("Sec-WebSocket-Key")),
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
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|_| ConnectionError::WriteHandshakeFailed)?;

        let codec =
            crate::codec::WebsocketCodec::new(crate::codec::EndpointType::Server, max_frame_size);
        Ok(Connection {
            framed: tokio_util::codec::Framed::new(Box::new(stream), codec),
            max_frame_size,
            closed: false,
            last_ping: None,
            frag_opcode: None,
            frag_buffer: Vec::new(),
        })
    }
}
