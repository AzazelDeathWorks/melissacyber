use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Markdown,
    Pdf,
    Sarif,
    Html,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingReport {
    pub finding_id: Uuid,
    /// Runnable proof-of-concept — the deliverable that kills slop.
    pub poc: String,
    pub evidence_artifacts: Vec<Uuid>,
    pub remediation: String,
}
