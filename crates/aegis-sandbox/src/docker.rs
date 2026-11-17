//! Docker backend: hardened attack container on an isolated `--internal`
//! network, with all egress forced through the allowlist proxy.
//!
//! Layout per engagement:
//!   aegis-int-<id>    internal bridge (no direct internet)
//!   aegis-egress-<id> proxy process bound on the network gateway
//!   aegis-box-<id>    attack container (cap-drop ALL, no-new-privs)

use crate::backend::{BackendKind, SandboxBackend, SandboxHandle, SandboxSpec};
use crate::egress::{Allowlist, EgressProxy};
use std::net::{IpAddr, SocketAddr};
use tokio::process::Command;
use tracing::info;

pub struct DockerBackend;

impl DockerBackend {
    pub fn new() -> Self {
        Self
    }

    async fn sh(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
        let out = Command::new(cmd).args(args).output().await?;
        if !out.status.success() {
            anyhow::bail!(
                "{cmd} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Gateway IP of a docker network — where the egress proxy binds.
    async fn gateway(net: &str) -> anyhow::Result<IpAddr> {
        let gw = Self::sh(
            "docker",
            &[
                "network", "inspect", net, "-f",
                "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
            ],
        )
        .await?;
        gw.parse()
            .map_err(|_| anyhow::anyhow!("no gateway for {net}: '{gw}'"))
    }
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Extra runtime state attached to a docker-backed handle.
pub struct DockerSession {
    pub net: String,
    pub container: String,
    pub proxy_addr: SocketAddr,
}

#[async_trait::async_trait]
impl SandboxBackend for DockerBackend {
    async fn provision(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxHandle> {
        let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let net = format!("aegis-int-{id}");
        let container = format!("aegis-box-{id}");

        // 1. Internal-only bridge — no direct internet for the attack box.
        Self::sh("docker", &["network", "create", "--internal", &net]).await?;

        // 2. Egress proxy on the network gateway (default-deny allowlist).
        let gw = Self::gateway(&net).await?;
        let allow = Allowlist::new(&spec.egress_allow);
        let proxy = EgressProxy::run(SocketAddr::new(gw, 8080), allow).await?;

        // 3. Attack container — all HTTP(S) out via the proxy.
        let proxy_url = format!("http://{}:{}", proxy.ip(), proxy.port());
        let mut args: Vec<String> = vec![
            "run".into(), "-d".into(), "--name".into(), container.clone(),
            "--network".into(), net.clone(),
            "--cap-drop".into(), "ALL".into(),
            "--security-opt".into(), "no-new-privileges".into(),
            "--cpus".into(), spec.cpus.to_string(),
            "--memory".into(), format!("{}m", spec.mem_mb),
            "-e".into(), format!("HTTP_PROXY={proxy_url}"),
            "-e".into(), format!("HTTPS_PROXY={proxy_url}"),
            "-e".into(), "NO_PROXY=localhost,127.0.0.1".into(),
        ];
        // Sandbox tiers: gVisor/Kata isolate via OCI runtime when installed.
        let runtime = match spec.backend {
            BackendKind::GVisor => Some("runsc"),
            BackendKind::Firecracker => Some("kata-runtime"),
            _ => None,
        };
        if let Some(rt) = runtime {
            args.extend(["--runtime".to_string(), rt.to_string()]);
        }
        for m in &spec.mounts {
            args.extend(["-v".to_string(), m.clone()]);
        }
        args.extend([spec.image.clone(), "sleep".into(), "infinity".into()]);
        Self::sh("docker", &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await?;

        info!(%container, %net, "attack sandbox up");
        Ok(SandboxHandle {
            id: container,
            backend: spec.backend,
        })
    }

    async fn exec(&self, h: &SandboxHandle, cmd: &[&str]) -> anyhow::Result<String> {
        let mut args = vec!["exec", &h.id, "sh", "-lc"];
        let joined = cmd
            .iter()
            .map(|c| format!("'{}'", c.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        args.push(&joined);
        Self::sh("docker", &args).await
    }

    async fn destroy(&self, h: SandboxHandle) -> anyhow::Result<()> {
        let _ = Self::sh("docker", &["rm", "-f", &h.id]).await;
        // internal network name derives from the same id suffix
        if let Some(suffix) = h.id.strip_prefix("aegis-box-") {
            let _ = Self::sh(
                "docker",
                &["network", "rm", &format!("aegis-int-{suffix}")],
            )
            .await;
        }
        Ok(())
    }
}
