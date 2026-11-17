//! Minimal Chrome DevTools Protocol driver — real browser steering for the
//! agent: navigate, click, type, evaluate JS, screenshot, scroll. Runs a
//! throwaway headless Chrome on the host (per-call user-data-dir, always
//! killed afterwards). Scope enforcement stays in the tool layer; note the
//! browser's egress is the host network, so navigations are allowlist-gated
//! before being issued.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::process::Child;
use tokio_tungstenite::tungstenite::Message;

pub struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    next_id: u64,
    child: Child,
    profile_dir: std::path::PathBuf,
    /// Console/log events observed while waiting for command replies.
    pub events: Vec<String>,
}

impl Cdp {
    /// Launch headless chrome and attach to the first page target.
    pub async fn launch(chrome: &str) -> Result<Self, String> {
        let profile_dir =
            std::path::PathBuf::from(format!("/tmp/aegis-steer-{}", uuid::Uuid::new_v4()));
        let child = tokio::process::Command::new(chrome)
            .args([
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--remote-debugging-port=0",
                "--disable-dev-shm-usage",
                &format!("--user-data-dir={}", profile_dir.display()),
                "about:blank",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("chrome spawn: {e}"))?;

        // DevToolsActivePort file tells us the picked port.
        let port_file = profile_dir.join("DevToolsActivePort");
        let deadline = Instant::now() + Duration::from_secs(8);
        let port = loop {
            if let Ok(txt) = std::fs::read_to_string(&port_file) {
                if let Some(p) = txt.lines().next().and_then(|l| l.trim().parse::<u16>().ok()) {
                    break p;
                }
            }
            if Instant::now() > deadline {
                return Err("chrome did not publish DevToolsActivePort".into());
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        };

        let list: Value = reqwest::get(format!("http://127.0.0.1:{port}/json"))
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let ws_url = list
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|t| t["type"] == "page")
                    .or_else(|| a.first())
            })
            .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(String::from))
            .ok_or("no CDP page target")?;

        let (ws, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| format!("ws connect: {e}"))?;
        let mut c = Self {
            ws,
            next_id: 1,
            child,
            profile_dir,
            events: vec![],
        };
        c.cmd("Page.enable", json!({})).await?;
        c.cmd("Runtime.enable", json!({})).await?;
        Ok(c)
    }

    /// Send one CDP command and wait for its reply (events collected).
    pub async fn cmd(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"id": id, "method": method, "params": params});
        self.ws
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let next = tokio::time::timeout(Duration::from_secs(10), self.ws.next()).await;
            let Some(Some(Ok(Message::Text(txt)))) = next.ok() else {
                continue;
            };
            let v: Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
            if v["id"].as_u64() == Some(id) {
                if let Some(err) = v.get("error") {
                    return Err(format!("{method}: {err}"));
                }
                return Ok(v["result"].clone());
            }
            if let Some(m) = v["method"].as_str() {
                if self.events.len() < 200 {
                    self.events.push(format!("{m} {}", v["params"]));
                }
            }
        }
        Err(format!("{method}: reply timeout"))
    }

    pub async fn navigate(&mut self, url: &str, wait_ms: u64) -> Result<(), String> {
        self.cmd("Page.navigate", json!({"url": url})).await?;
        // wait for readyState complete (bounded)
        let deadline = Instant::now() + Duration::from_millis(wait_ms.max(1000));
        while Instant::now() < deadline {
            if let Ok(v) = self
                .eval("document.readyState")
                .await
            {
                if v.as_str() == Some("complete") {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }

    /// Evaluate JS, returning by value.
    pub async fn eval(&mut self, expr: &str) -> Result<Value, String> {
        let r = self
            .cmd(
                "Runtime.evaluate",
                json!({
                    "expression": expr,
                    "awaitPromise": true,
                    "returnByValue": true,
                }),
            )
            .await?;
        if r["exceptionDetails"].is_object() {
            return Err(format!("js exception: {}", r["exceptionDetails"]));
        }
        Ok(r["result"]["value"].clone())
    }

    /// Full page DOM + current URL.
    pub async fn snapshot(&mut self) -> Result<(String, String), String> {
        let dom = self
            .eval("document.documentElement.outerHTML")
            .await?
            .as_str()
            .unwrap_or("")
            .to_string();
        let url = self
            .eval("location.href")
            .await?
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok((dom, url))
    }

    pub async fn screenshot(&mut self) -> Result<Vec<u8>, String> {
        let r = self
            .cmd("Page.captureScreenshot", json!({"format": "png"}))
            .await?;
        let b64 = r["data"].as_str().unwrap_or("");
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| e.to_string())
    }

    pub async fn close(mut self) {
        let _ = self.child.kill().await;
        let _ = std::fs::remove_dir_all(&self.profile_dir);
    }
}
