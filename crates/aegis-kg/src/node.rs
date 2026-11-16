use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type NodeId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Asset,
    Endpoint,
    Param,
    Tech,
    Fact,
    Finding,
    Evidence,
    Hypothesis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Has,
    Uses,
    TestedWith,
    Produces,
    ChainsTo,
    DependsOn,
    Proves,
}

/// Who learned this and how — audit trail for every fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub agent_id: Uuid,
    pub tool: String,
    pub at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub label: String,
    pub data: serde_json::Value,
    pub provenance: Option<Provenance>,
}
