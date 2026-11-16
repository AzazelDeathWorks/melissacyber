//! Hard limits: tokens, USD, wall-clock, parallel agents.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub max_usd: Option<f64>,
    pub max_agents: usize,
    pub max_parallel: usize,
    pub wall_clock_secs: Option<u64>,
    pub spent_usd: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_usd: Some(10.0),
            max_agents: 500,
            max_parallel: 16,
            wall_clock_secs: Some(7200),
            spent_usd: 0.0,
        }
    }
}

impl Budget {
    pub fn exhausted(&self) -> bool {
        self.max_usd.is_some_and(|m| self.spent_usd >= m)
    }
}
