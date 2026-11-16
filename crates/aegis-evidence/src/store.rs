use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

impl ArtifactStore {
    pub fn add(&mut self, kind: &str, path: String, contents: &[u8]) -> Uuid {
        let id = Uuid::new_v4();
        self.artifacts.push(Artifact {
            id,
            kind: kind.into(),
            sha256: format!("{:x}", Sha256::digest(contents)),
            path,
        });
        id
    }
}
