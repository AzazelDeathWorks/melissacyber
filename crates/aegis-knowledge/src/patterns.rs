//! Verified findings become few-shot patterns for future engagements
//! (opt-in, local-only experience flywheel).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub vuln_class: String,
    pub context_signature: String,
    pub payload_template: String,
    pub times_verified: u32,
}

#[derive(Default)]
pub struct PatternLibrary {
    pub patterns: Vec<Pattern>,
}
