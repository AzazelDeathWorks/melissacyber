//! aegis-core — orchestration engine.
//!
//! XBOW pattern: a persistent [`Coordinator`] plans over a probabilistic
//! attack graph and spawns short-lived [`Solver`] agents. Every solver is
//! born with fresh context for a single objective and retired afterwards,
//! so hypothesis bias never accumulates.

pub mod agent;
pub mod budget;
pub mod coordinator;
pub mod engagement;
pub mod pag;

pub use agent::{Agent, AgentId, AgentKind, AgentSpec, AgentState};
pub use budget::Budget;
pub use coordinator::Coordinator;
pub use engagement::{Engagement, EngagementId, Mode};
pub use pag::{AttackGraph, AttackStep, EdgeKind};
