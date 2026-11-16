use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Result of replaying the attack against the patched target / new rule:
/// exploit blocked + alert fired = vaccine verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub finding_id: Uuid,
    pub exploit_blocked: bool,
    pub alert_fired: bool,
}
