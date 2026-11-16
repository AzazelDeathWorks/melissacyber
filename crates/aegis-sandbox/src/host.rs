//! Host fallback backend — NO isolation. For local dev/tests against a
//! lab target only. Docker remains the default for real engagements.

use crate::backend::{BackendKind, SandboxBackend, SandboxHandle, SandboxSpec};
use async_trait::async_trait;
use tracing::warn;

pub struct HostBackend;

#[async_trait]
impl SandboxBackend for HostBackend {
    async fn provision(&self, _spec: &SandboxSpec) -> anyhow::Result<SandboxHandle> {
        warn!("HOST backend: commands run un-sandboxed — use only against lab targets");
        Ok(SandboxHandle { id: "host".into(), backend: BackendKind::Docker })
    }
    async fn exec(&self, _h: &SandboxHandle, cmd: &[&str]) -> anyhow::Result<String> {
        let out = tokio::process::Command::new("sh")
            .arg("-lc")
            .arg(cmd.join(" "))
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr))
    }
    async fn destroy(&self, _h: SandboxHandle) -> anyhow::Result<()> {
        Ok(())
    }
}
