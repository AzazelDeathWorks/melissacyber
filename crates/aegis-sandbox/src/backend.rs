use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Docker,
    GVisor,
    Firecracker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub backend: BackendKind,
    /// kali-aegis image or Firecracker rootfs
    pub image: String,
    pub cpus: u32,
    pub mem_mb: u32,
    /// Mount allowlist — system dirs and credential dirs are refused.
    pub mounts: Vec<String>,
    /// Hosts the egress proxy may reach (scope allowlist). Empty = deny all.
    #[serde(default)]
    pub egress_allow: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SandboxHandle {
    pub id: String,
    pub backend: BackendKind,
}

/// Container/microVM lifecycle. Docker impl lands in Faz 1; gVisor and
/// Firecracker behind feature parity later.
#[async_trait::async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn provision(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxHandle>;
    async fn exec(&self, h: &SandboxHandle, cmd: &[&str]) -> anyhow::Result<String>;
    async fn destroy(&self, h: SandboxHandle) -> anyhow::Result<()>;
}
