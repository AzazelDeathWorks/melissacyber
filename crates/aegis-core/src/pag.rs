//! Probabilistic Attack Graph (PAG) — the coordinator's brain.
//!
//! Every attack step is a DAG node: required facts -> action -> yielded
//! facts. Edges carry success probability and cost; the coordinator picks
//! the next edge by expected utility (ChainPen/MulVAL neuro-symbolic
//! pattern). Findings are validated before they become facts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub type StepId = Uuid;
pub type FactId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Enables,
    Chains,
    Alternative,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub id: StepId,
    /// Solver type suited to this step.
    pub agent_kind: crate::agent::AgentKind,
    pub hypothesis: String,
    /// Facts that must hold before this step runs.
    pub requires: Vec<FactId>,
    /// Facts produced on success.
    pub yields: Vec<FactId>,
    /// Prior success probability (updated by ensemble results).
    pub p_success: f64,
    /// Estimated cost in USD-equivalent tokens/time.
    pub cost: f64,
    pub status: StepStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Exhausted,
}

#[derive(Debug, Default)]
pub struct AttackGraph {
    pub steps: BTreeMap<StepId, AttackStep>,
    pub edges: Vec<(StepId, StepId, EdgeKind)>,
}

impl AttackGraph {
    /// Expected utility = p_success * value / cost. Picks the frontier
    /// step whose requirements are satisfied.
    pub fn next_frontier(&self, known: &[FactId]) -> Option<StepId> {
        self.steps
            .values()
            .filter(|s| s.status == StepStatus::Pending)
            .filter(|s| s.requires.iter().all(|f| known.contains(f)))
            .max_by(|a, b| {
                let ua = a.p_success / a.cost.max(1e-6);
                let ub = b.p_success / b.cost.max(1e-6);
                ua.partial_cmp(&ub).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|s| s.id)
    }
}
