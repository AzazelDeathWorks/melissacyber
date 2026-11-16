//! The persistent decision engine (XBOW coordinator pattern).

use crate::agent::AgentSpec;
use crate::pag::AttackGraph;
use tracing::info;

/// Owns the OPPLAN: reads the engagement scope, grows the attack graph,
/// spawns/retires solvers, debriefs results, picks the next move.
pub struct Coordinator {
    pub graph: AttackGraph,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            graph: AttackGraph::default(),
        }
    }

    /// Main loop: plan -> spawn -> debrief -> update PAG -> repeat until
    /// budget or frontier exhausted. Faz 1 implementation target.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("coordinator: engagement loop start");
        // TODO(Faz 1): discovery wave -> graph frontier -> solver spawn
        // -> critic -> validator_submit -> KG update -> repeat
        Ok(())
    }

    /// Build the task spec handed to a freshly born solver.
    pub fn next_task(&self) -> Option<AgentSpec> {
        let _ = self.graph;
        None
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}
