//! Default-deny egress proxy — scope enforced at the network layer.
//!
//! Attack containers live on an `--internal` docker network: the only
//! reachable host is this proxy. CONNECT and plain-HTTP requests are
//! allowed only to allowlisted hosts; everything else is refused before
//! a single byte leaves. Prompt-level scope lists can be bypassed by a
//! confused agent; iptables/proxy cannot.

use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct Allowlist {
    /// Exact hosts or suffix rules (".example.com" covers subdomains).
    hosts: HashSet<String>,
}

impl Allowlist {
    pub fn new(entries: &[String]) -> Self {
        Self {
            hosts: entries.iter().map(|e| e.to_ascii_lowercase()).collect(),
        }
    }

    pub fn allows(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        if self.hosts.contains(&h) {
            return true;
        }
        self.hosts.iter().any(|rule| {
            rule.starts_with('.') && (h.ends_with(rule) || h == &rule[1..])
        })
    }
}

pub struct EgressProxy {
    pub addr: SocketAddr,
    allow: Allowlist,
}

impl EgressProxy {
    /// Bind on `bind` (e.g. the internal bridge gateway IP) and serve
    /// until the task is dropped.
    pub async fn run(bind: SocketAddr, allow: Allowlist) -> anyhow::Result<SocketAddr> {
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        info!(%addr, "egress proxy up (default-deny)");
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let allow = allow.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle(stream, &allow).await {
                                warn!(%peer, error=%e, "egress conn failed");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error=%e, "egress accept failed");
                    }
                }
            }
        });
        Ok(addr)
    }
}

async fn handle(mut client: TcpStream, allow: &Allowlist) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1
        let host = target.split(':').next().unwrap_or("");
        let port: u16 = target.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(443);
        return tunnel(client, host, port, allow, true).await;
    }

    // Plain HTTP absolute-URI: GET http://host/path HTTP/1.1
    let host = target
        .strip_prefix("http://")
        .and_then(|r| r.split('/').next())
        .or_else(|| {
            lines
                .clone()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .map(|l| l[5..].trim())
        })
        .unwrap_or("");
    let host_only = host.split(':').next().unwrap_or("");
    if !allow.allows(host_only) {
        warn!(host = host_only, "egress DENIED (out of scope)");
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 15\r\n\r\nout of scope\n")
            .await?;
        return Ok(());
    }
    let port: u16 = host.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    let mut upstream = TcpStream::connect((host_only, port)).await?;
    upstream.write_all(&buf[..n]).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

async fn tunnel(
    mut client: TcpStream,
    host: &str,
    port: u16,
    allow: &Allowlist,
    ack: bool,
) -> anyhow::Result<()> {
    if !allow.allows(host) {
        warn!(host, "egress CONNECT DENIED (out of scope)");
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await?;
        return Ok(());
    }
    let mut upstream = TcpStream::connect((host, port)).await?;
    if ack {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_exact_and_suffix() {
        let a = Allowlist::new(&[
            "app.example.com".into(),
            ".corp.io".into(),
            "10.0.0.5".into(),
        ]);
        assert!(a.allows("app.example.com"));
        assert!(a.allows("api.corp.io"));
        assert!(a.allows("corp.io"));
        assert!(a.allows("10.0.0.5"));
        assert!(!a.allows("evil.com"));
        assert!(!a.allows("notapp.example.com.evil.com"));
        assert!(!a.allows("othercorp.io"));
    }
}
