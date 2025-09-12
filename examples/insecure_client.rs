use allagan_websocket::Connection;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Address and host for the WebSocket server (non-TLS)
    let host = "echo.websocket.org";
    let path = "/";
    let max_frame_size = 4096;

    // Connect TCP (port 80 for insecure WebSocket)
    let stream = TcpStream::connect((host, 80)).await?;

    // Perform the WebSocket handshake (no TLS)
    let mut conn = Connection::new_insecure_client(stream, host, path, max_frame_size).await?;

    // Send a text message
    conn.send_text("Hello, insecure WebSocket!").await?;

    // Wait for a response
    while let Some(msg) = conn.next_message().await {
        println!("Received: {:?}", msg?);
    }

    Ok(())
}
