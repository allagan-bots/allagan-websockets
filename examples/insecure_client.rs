//! An example of a client that doesn't use TLS termination

use allagan_websocket::Connection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Address and host for the WebSocket server (non-TLS)
    let uri = http::Uri::from_static("ws://echo.websocket.org/");
    let max_frame_size = 4096;

    // Create the connection (no TLS)
    let mut conn = Connection::builder(uri, max_frame_size).connect().await?;

    // Send a text message
    conn.send_text("Hello, insecure WebSocket!").await?;

    // Wait for a response
    while let Some(msg) = conn.next_message().await {
        println!("Received: {:?}", msg?);
    }

    Ok(())
}
