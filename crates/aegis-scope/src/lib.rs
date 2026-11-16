//! aegis-scope — scope.yaml schema + RoE policy.
//!
//! Authorization is a file, a signature, and a network rule — not a
//! prompt suggestion.

pub mod roe;
pub mod schema;

pub use roe::Roe;
pub use schema::{Scope, Target, TargetKind};
