//! An engagement: scope + RoE + mode + artifacts.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type EngagementId = Uuid;

/// Engagement mode — the red/blue/purple loop nobody else ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Red,
    Blue,
    Purple,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub id: EngagementId,
    pub mode: Mode,
    pub budget: crate::budget::Budget,
}
