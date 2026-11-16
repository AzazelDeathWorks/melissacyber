//! Role-based routing: `models.yaml` maps agent roles to provider/model
//! pairs, with retry + fallback chains and budget accounting.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub role: String,
    /// e.g. "anthropic/claude-opus-4.5", "ollama/whiterabbitneo-70b"
    pub model: String,
    pub fallback: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ModelRouter {
    pub assignments: BTreeMap<String, RoleAssignment>,
}

impl ModelRouter {
    pub fn resolve(&self, role: &str) -> Option<&RoleAssignment> {
        self.assignments.get(role)
    }
}
