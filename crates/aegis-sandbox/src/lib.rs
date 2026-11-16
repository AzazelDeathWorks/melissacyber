//! aegis-sandbox — isolation backends.
//!
//! Three profiles: `docker` (default local, hardened container),
//! `gvisor` (runsc, for running hostile exploit code), `firecracker`
//! (microVM, cloud/multi-tenant). The sandbox job is bidirectional:
//! keep agent/exploit code off the operator machine, and keep
//! engagements isolated from each other.

pub mod backend;
pub mod network;

pub use backend::{BackendKind, SandboxBackend, SandboxHandle, SandboxSpec};
pub use network::EgressPolicy;
