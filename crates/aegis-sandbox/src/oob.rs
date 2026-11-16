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

/// Minimal HTTP sink: records method+path for every request, replies 200.
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
                        let mut buf = vec![0u8; 8192];
                        if let Ok(n) = s.read(&mut buf).await {
                            let head = String::from_utf8_lossy(&buf[..n]);
                            let mut parts = head.split_whitespace();
                            let method = parts.next().unwrap_or("").to_string();
                            let path = parts.nth(0).unwrap_or("").to_string();
                            let token = path.trim_start_matches('/').split('/').next().unwrap_or("").to_string();
                            if !token.is_empty() {
                                store.record(OobHit {
                                    token,
                                    method,
                                    path,
                                    remote: peer.to_string(),
                                });
                            }
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
