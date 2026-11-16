use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    WebApp,
    ApiSpec,
    IpRange,
    Repository,
    LocalCode,
    CloudAccount,
    ContainerLab,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
    /// Local checkout path for code targets.
    pub workspace_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub targets: Vec<Target>,
    /// Domains/CIDRs the egress proxy may reach.
    pub egress_allow: Vec<String>,
    pub roe: crate::roe::Roe,
}
