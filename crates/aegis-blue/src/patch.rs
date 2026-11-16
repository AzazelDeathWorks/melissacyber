use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A proposed fix for a verified finding: diff + rationale + which test
/// suite must pass (Atlantis P4 pattern: generate, build, test).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchProposal {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub diff: String,
    pub rationale: String,
}
