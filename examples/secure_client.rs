use allagan_websocket::new_secure_client;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Address and host for the WebSocket server
    let host = "echo.websocket.org";
    let path = "/";
    let max_frame_size = 4096;

    // Connect TCP
    let stream = TcpStream::connect((host, 443)).await?;

    // Perform the WebSocket + TLS handshake
    let mut conn = new_secure_client(stream, host, path, max_frame_size, None).await?;

    // Send a text message
    conn.send_text("Hello, secure WebSocket!").await?;

    // Wait for a response
    while let Some(msg) = conn.next_message().await {
        println!("Received: {:?}", msg?);
    }

    Ok(())
}
