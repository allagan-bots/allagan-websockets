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

## Development

### Code Formatting

This project uses `rustfmt` to ensure consistent code formatting. Before submitting a pull request, make sure your code is properly formatted:

```bash
cargo fmt
```

To check if your code is formatted correctly:

```bash
cargo fmt --check
```

The CI pipeline will automatically check formatting and fail if any files need formatting.

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

## Documentation

See [docs.rs](https://docs.rs/allagan-websocket) for full API documentation.

## License

MIT or Apache 2.0, at the user's choice