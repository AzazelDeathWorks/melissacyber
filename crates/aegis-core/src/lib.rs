//! aegis-core — orchestration engine.
//!
//! XBOW pattern: a persistent [`Coordinator`] plans over a probabilistic
//! attack graph and spawns short-lived [`Solver`] agents. Every solver is
//! born with fresh context for a single objective and retired afterwards,
//! so hypothesis bias never accumulates.

pub mod agent;
pub mod arena;
pub mod budget;
pub mod coordinator;
pub mod engagement;
pub mod fuzz;
pub mod pag;
pub mod prompts;
pub mod runner;
pub mod search;
pub mod spec_loader;

pub use arena::{apply, append_trace, judge, rule_matches, ArenaScore, ArenaTrace};
pub use agent::{Agent, AgentId, AgentKind, AgentSpec, AgentState};
pub use budget::Budget;
pub use coordinator::{Coordinator, EndpointTask};
pub use fuzz::{fuzz_run, propose_inputs, seed_inputs, Crash};
pub use engagement::{run_engagement, Engagement, EngagementCtx, EngagementId, EngagementResult, Mode, ProviderFor};
pub use pag::{AttackGraph, AttackStep, EdgeKind};
pub use runner::{run_agent, AgentOutcome};
