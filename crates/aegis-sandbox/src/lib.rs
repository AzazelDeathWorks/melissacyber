//! aegis-sandbox — isolation backends.
//!
//! Three profiles: `docker` (default local, hardened container),
//! `gvisor` (runsc, for running hostile exploit code), `firecracker`
//! (microVM, cloud/multi-tenant). The sandbox job is bidirectional:
//! keep agent/exploit code off the operator machine, and keep
//! engagements isolated from each other.

pub mod backend;
pub mod docker;
pub mod egress;
pub mod oob;
pub mod host;
pub mod network;
pub mod rate;

pub use backend::{BackendKind, SandboxBackend, SandboxHandle, SandboxSpec};
pub use docker::DockerBackend;
pub use host::HostBackend;
pub use egress::{Allowlist, EgressProxy};
pub use oob::{run_oob_dns, run_oob_server, OobHit, OobStore};
pub use network::EgressPolicy;
pub use rate::RateLimiter;
