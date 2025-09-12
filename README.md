# allagan-websocket

A lightweight Rust crate for WebSocket communication, designed for reliability and ease of use. Built to integrate seamlessly with async Rust applications.

## Features

- Async WebSocket client and server support
- Simple API for sending and receiving messages
- Built-in error handling
- Lightweight and dependency-minimal

## Usage

Add to your `Cargo.toml`:

```toml
allagan-websocket = "0.1"
```

## Examples

| Example                                          | Description                             |
| ------------------------------------------------ | --------------------------------------  |
| [Insecure Client](./examples/insecure_client.rs) | Creates a connection to a ws:// server  |
| [Secure Client](./examples/secure_client.rs)     | Creates a connection to a wss:// server |

## Documentation

See [docs.rs](https://docs.rs/allagan-websocket) for full API documentation.

## License

MIT or Apache 2.0, at the user's choice