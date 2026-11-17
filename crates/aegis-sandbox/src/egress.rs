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

    /// Canonicalize host strings so literal tricks don't bypass rules:
    /// "127.1", "0x7f.0.0.1", "2130706433", "0177.0.0.1", "[::1]", "::1",
    /// trailing-dot FQDNs, percent-encoded hosts.
    pub fn normalize(host: &str) -> String {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let h = h.trim_start_matches('[').trim_end_matches(']').to_string();
        // ::1 and friends -> 127.0.0.1
        if h == "::1" || h == "0:0:0:0:0:0:0:1" {
            return "127.0.0.1".into();
        }
        // IPv4 in weird notations: dotless int, hex/octal per-octet, short forms.
        let mut octets: Vec<u64> = vec![];
        let mut ok = true;
        for part in h.split('.') {
            let v = if let Some(x) = part.strip_prefix("0x") {
                u64::from_str_radix(x, 16).ok()
            } else if part.len() > 1 && part.starts_with('0') {
                u64::from_str_radix(part, 8).ok()
            } else {
                part.parse::<u64>().ok()
            };
            match v {
                Some(v) => octets.push(v),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        // All octets but the last must be <= 0xff; the last group carries
        // the remaining bytes: n=1->32 bits, 2->24 bits, 3->16 bits, 4->8 bits.
        let n = octets.len();
        let in_range = (1..=4).contains(&n);
        let last_max: u64 = if in_range {
            [0, 0xffFFffFF, 0xffFFff, 0xffFF, 0xff][n]
        } else {
            0
        };
        let head_ok = in_range && octets[..n - 1].iter().all(|o| *o <= 0xff);
        if ok && in_range && head_ok && octets[n - 1] <= last_max {
            let addr: u64 = match n {
                // 127.1 == 127.0.0.1 ; 127.0.1 == 127.0.0.1
                1 => octets[0],
                2 => (octets[0] << 24) | octets[1],
                3 => (octets[0] << 24) | (octets[1] << 16) | octets[2],
                4 => (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3],
                _ => unreachable!(),
            };
            if addr <= u32::MAX as u64 {
                return format!(
                    "{}.{}.{}.{}",
                    (addr >> 24) & 0xff,
                    (addr >> 16) & 0xff,
                    (addr >> 8) & 0xff,
                    addr & 0xff
                );
            }
        }
        h
    }

    pub fn allows(&self, host: &str) -> bool {
        let h = Self::normalize(host);
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
