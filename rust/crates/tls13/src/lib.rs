//! TLS 1.3 selective MPC engine for one-shot HTTP requests.
//!
//! Implements a constrained RFC 8446 profile with a real garbled-circuit path.
//! The shared sidecar enables this engine explicitly with `--tls-version 1.3`.
//! See the crate README for security boundaries and integration constraints.
//!
//! Hub is the honest garbler; Provider is the evaluator. Output decoding uses
//! MAC authentication and fresh Hub-private masks to keep secrets Hub-only.
#![forbid(unsafe_code)]

mod engine;
mod mpc;
mod record;
mod schedule;
mod wire;
pub use engine::{Hub, Policy, Provider, hub_handshake, provider_handshake};

/// Engine error; callers must destroy a failed session.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
/// Engine operation result.
pub type Result<T> = std::result::Result<T, Error>;

fn fail(message: &'static str) -> Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}
