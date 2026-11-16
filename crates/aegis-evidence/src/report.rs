//! Report rendering: verified findings -> bug-bounty-grade Markdown
//! (PDF/SARIF adapters next).

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

/// Render verified findings to Markdown. `entries`: (title, severity,
/// class, reproduction, evidence-json).
pub fn render_markdown(
    engagement_id: Uuid,
    entries: &[(String, String, String, String, String)],
) -> String {
    let mut s = format!(
        "# melissacyber engagement report\n\nengagement: `{engagement_id}`\n\n\
         {} verified finding(s) — every entry reproduced by non-AI validators.\n\n",
        entries.len()
    );
    for (i, (title, sev, class, repro, evidence)) in entries.iter().enumerate() {
        s.push_str(&format!(
            "## {}. {} `[{}] [class:{}]`\n\n**Proof:** {}\n\n```json\n{}\n```\n\n",
            i + 1,
            title,
            sev,
            class,
            repro,
            evidence,
        ));
    }
    s
}
