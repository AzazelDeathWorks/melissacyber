use serde::{Deserialize, Serialize};

/// A domain pack: agent defs + tool set + validators + playbooks for one
/// target class (web, api, network/ad, cloud, binary, mobile,
/// smart-contract, llm-target, supply-chain, saas-config, iot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgePack {
    pub name: String,
    pub version: String,
    pub playbooks: Vec<String>,
    pub agents: Vec<String>,
    pub tools: Vec<String>,
}
