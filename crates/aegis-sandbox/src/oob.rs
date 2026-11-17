//! Out-of-band interaction server (own interactsh-class listener).
//!
//! Agents mint token URLs; the target's outbound call hits this listener;
//! validators correlate token -> hits. Blind SSRF/XSS/XXE become
//! provable without an agent's guesswork.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobHit {
    pub token: String,
    pub method: String,
    pub path: String,
    pub remote: String,
    /// Full request evidence: headers + body (auth leaks, blind exfil).
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Default, Clone)]
pub struct OobStore {
    hits: Arc<Mutex<HashMap<String, Vec<OobHit>>>>,
}

impl OobStore {
    pub fn record(&self, hit: OobHit) {
        self.hits.lock().unwrap().entry(hit.token.clone()).or_default().push(hit);
    }
    pub fn hits_for(&self, token: &str) -> Vec<OobHit> {
        self.hits.lock().unwrap().get(token).cloned().unwrap_or_default()
    }
}

/// Minimal HTTP sink: records method+path+headers+body per request.
pub async fn run_oob_server(bind: SocketAddr, store: OobStore) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    info!(%addr, "oob interaction server up");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut s, peer)) => {
                    let store = store.clone();
                    tokio::spawn(async move {
                        let mut data = Vec::new();
                        let mut buf = [0u8; 8192];
                        // read headers fully, then body by content-length
                        let header_end = loop {
                            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                                break pos + 4;
                            }
                            if data.len() > 128 * 1024 {
                                break data.len();
                            }
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => break data.len(),
                                Ok(n) => data.extend_from_slice(&buf[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&data[..header_end.min(data.len())]).to_string();
                        let mut lines = head.split("\r\n");
                        let reqline = lines.next().unwrap_or("");
                        let mut parts = reqline.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();
                        let mut clen = 0usize;
                        let headers: Vec<String> = lines
                            .filter(|l| !l.is_empty())
                            .map(|l| {
                                if let Some((k, v)) = l.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        clen = v.trim().parse().unwrap_or(0);
                                    }
                                }
                                l.to_string()
                            })
                            .collect();
                        let mut body = data[header_end.min(data.len())..].to_vec();
                        while body.len() < clen {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => body.extend_from_slice(&buf[..n]),
                            }
                        }
                        let token = path.trim_start_matches('/').split('/').next().unwrap_or("").to_string();
                        if !token.is_empty() {
                            store.record(OobHit {
                                token,
                                method,
                                path,
                                remote: peer.to_string(),
                                headers,
                                body: String::from_utf8_lossy(&body[..body.len().min(clen)]).to_string(),
                            });
                        }
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
                    });
                }
                Err(_) => break,
            }
        }
    });
    Ok(addr)
}

/// OOB DNS listener: answers every A query with 127.0.0.1 and records the
/// queried name — token = the first label. Blind exfil via DNS works even
/// where the target can't make HTTP requests.
pub async fn run_oob_dns(bind: SocketAddr, store: OobStore) -> anyhow::Result<SocketAddr> {
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    let addr = sock.local_addr()?;
    info!(%addr, "oob dns listener up");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
            if n < 12 {
                continue;
            }
            let pkt = &buf[..n];
            // Walk the QNAME (starts at byte 12).
            let mut name = String::new();
            let mut i = 12usize;
            while i < n && pkt[i] != 0 {
                let len = pkt[i] as usize;
                i += 1;
                if i + len > n {
                    break;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(&pkt[i..i + len]));
                i += len;
            }
            if name.is_empty() {
                continue;
            }
            let token = name.split('.').next().unwrap_or("").to_string();
            if !token.is_empty() {
                store.record(OobHit {
                    token,
                    method: "DNS".into(),
                    path: name.clone(),
                    remote: peer.to_string(),
                    headers: vec![],
                    body: String::new(),
                });
            }
            // Minimal DNS reply: copy header, set QR=1, answer A 127.0.0.1.
            let mut resp = Vec::with_capacity(n + 16);
            resp.extend_from_slice(pkt);
            resp[2] |= 0x80; // QR
            resp[7] = 1; // ANCOUNT = 1 (bytes 6-7 big-endian; 6 stays 0)
            if i + 4 <= n {
                // answer: name ptr | type A | class IN | ttl | rdlen 4 | 127.0.0.1
                resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
                resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
                resp.extend_from_slice(&[0x00, 0x04, 127, 0, 0, 1]);
            }
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    Ok(addr)
}
