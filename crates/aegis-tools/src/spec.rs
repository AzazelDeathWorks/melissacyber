//! Tool contract.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for arguments.
    pub schema: serde_json::Value,
    /// Roles allowed to call it — keeps each agent's tool surface small.
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub ok: bool,
    pub data: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("scope violation: {0}")]
    ScopeViolation(String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
    #[error("timeout")]
    Timeout,
    #[error("policy: {0}")]
    Policy(String),
    #[error("net error: {0}")]
    Net(String),
}

/// Tier-A wrappers (implemented inside the sandbox or against its
/// control plane): terminal(tmux), http_client, browser, python_repl,
/// file_ops, kg_query/kg_write, validator_submit, oob_canary,
/// scope_check, cred_vault, artifact_store, spawn_agent, ask_human,
/// budget_status.
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    async fn call(&self, args: serde_json::Value) -> Result<ToolOutput, ToolError>;
}
