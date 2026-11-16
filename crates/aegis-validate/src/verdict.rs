use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum Verdict {
    /// Reproduced deterministically — enters the report.
    Verified { reproduction: String },
    /// Could not be reproduced — dropped, reason logged.
    Rejected { reason: String },
    /// Preview class — reported as unverified.
    Preview { note: String },
}
