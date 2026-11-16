use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleFormat {
    Sigma,
    Suricata,
    Yara,
}

/// TTP -> MITRE ATT&CK mapped detection artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub format: RuleFormat,
    pub attck: Vec<String>,
    pub content: String,
}
