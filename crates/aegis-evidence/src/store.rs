use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: Uuid,
    pub kind: String,
    /// sha256 of contents — evidence integrity.
    pub sha256: String,
    pub path: String,
}

#[derive(Default)]
pub struct ArtifactStore {
    pub artifacts: Vec<Artifact>,
}
