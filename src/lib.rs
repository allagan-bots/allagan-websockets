//! WebSocket protocol implementation.
//!
//! This module provides the necessary types and functions to work with the WebSocket
//! protocol, including framing, encoding, and decoding.
//! It supports both client and server endpoints and handles various WebSocket features
//! such as text and binary messages, ping/pong frames, and connection closing.
//!
//! This crate does not handle any extension negotiation. It focuses solely on the
//! WebSocket protocol as defined in RFC 6455.
pub(crate) mod codec;
pub(crate) mod connection;
pub(crate) mod errors;

pub use connection::{ClientConnectionBuilder, Connection, WebsocketMessage};
pub use http;
