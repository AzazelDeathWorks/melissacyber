//! `aegis serve --mcp` — exposes the harness to external agents over
//! MCP-flavored JSON-RPC/HTTP. Real tools, no stubs:
//!   aegis_scope_check  {host}          -> in/out of scope
//!   aegis_oob          {action,token}  -> mint callback URL / fetch hits
//!   aegis_validate     {class,title,evidence} -> runs the deterministic validator

use aegis_sandbox::{Allowlist, OobStore};
use aegis_validate::{Finding, FindingClass, Severity, ValidatorRegistry, Verdict};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

pub struct McpState {
    pub allow: Allowlist,
    pub validators: Arc<ValidatorRegistry>,
    pub oob: OobStore,
    pub oob_base: String,
    /// Distributed worker queue: jobs deque'd by `aegis worker`.
    pub jobs: Mutex<VecDeque<Value>>,
    pub results: Mutex<Vec<Value>>,
}

fn tool_list() -> Value {
    json!({"tools":[
        {"name":"aegis_scope_check","description":"Is a host inside the authorized engagement scope","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}},
        {"name":"aegis_oob","description":"Mint OOB callback URL or list hits for a token","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["mint","hits"]},"token":{"type":"string"}},"required":["action"]}},
        {"name":"aegis_validate","description":"Run a deterministic validator on a candidate finding","inputSchema":{"type":"object","properties":{"class":{"type":"string"},"severity":{"type":"string"},"title":{"type":"string"},"evidence":{"type":"object"}},"required":["class","title","evidence"]}}
    ]})
}

fn parse_class(s: &str) -> FindingClass {
    match s {
        "sqli" => FindingClass::Sqli,
        "xss" => FindingClass::Xss,
        "ssrf" => FindingClass::Ssrf,
        "cmd" | "cmd_injection" => FindingClass::CmdInjection,
        "ssti" => FindingClass::Ssti,
        "file_path" | "lfi" => FindingClass::FilePath,
        _ => FindingClass::Other,
    }
}

async fn call_tool(st: &McpState, name: &str, args: &Value) -> Value {
    match name {
        "aegis_scope_check" => {
            let host = args["host"].as_str().unwrap_or("");
            json!({"target": host, "in_scope": st.allow.allows(host)})
        }
        "aegis_oob" => match args["action"].as_str().unwrap_or("") {
            "mint" => {
                let t = uuid::Uuid::new_v4().simple().to_string();
                json!({"token": t, "url": format!("{}/{}/cb", st.oob_base, t)})
            }
            "hits" => json!({"hits": st.oob.hits_for(args["token"].as_str().unwrap_or(""))}),
            a => json!({"error": format!("bad action {a}")}),
        },
        "aegis_validate" => {
            let f = Finding {
                id: uuid::Uuid::new_v4(),
                class: parse_class(args["class"].as_str().unwrap_or("")),
                severity: Severity::High,
                title: args["title"].as_str().unwrap_or("").into(),
                evidence: args["evidence"].clone(),
                verified: false,
            };
            match st.validators.get(&f.class) {
                Some(v) => match v.validate(&f).await {
                    Verdict::Verified { reproduction } => {
                        json!({"verdict":"verified","reproduction":reproduction})
                    }
                    Verdict::Rejected { reason } => json!({"verdict":"rejected","reason":reason}),
                    Verdict::Preview { note } => json!({"verdict":"preview","note":note}),
                },
                None => json!({"verdict":"error","reason":"no validator for class"}),
            }
        }
        _ => json!({"error": "unknown tool"}),
    }
}

async fn handle_rpc(st: &McpState, req: &Value) -> Value {
    let method = req["method"].as_str().unwrap_or("");
    let id = req["id"].clone();
    let result = match method {
        "initialize" => json!({
            "protocolVersion":"2024-11-05",
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"melissacyber","version":env!("CARGO_PKG_VERSION")}
        }),
        "tools/list" | "tools%2Flist" => tool_list(),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            let args = &req["params"]["arguments"];
            json!({"content":[{"type":"text","text":call_tool(st, name, args).await.to_string()}]})
        }
        "notifications/initialized" | "ping" => json!({}),
        _ => json!({"error":{"code":-32601,"message":format!("method {method}")}}),
    };
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

async fn read_http(sock: &mut tokio::net::TcpStream) -> Option<(String, String)> {
    let mut buf = vec![0u8; 65536];
    let n = sock.read(&mut buf).await.ok()?;
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let (head, body) = req.split_once("\r\n\r\n").unwrap_or((&req, ""));
    let line = head.lines().next().unwrap_or("");
    let method = line.split_whitespace().next().unwrap_or("GET").to_string();
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    Some((method + " " + &path, body.to_string()))
}

pub async fn serve(state: Arc<McpState>, bind: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "melissacyber MCP/worker server up");
    loop {
        let (mut sock, _) = listener.accept().await?;
        let st = state.clone();
        tokio::spawn(async move {
            let Some((path, body)) = read_http(&mut sock).await else { return };
            let (status, out): (&str, String) = match path.as_str() {
                // ---- MCP JSON-RPC ----
                p if p.ends_with("/mcp") || p == "POST /" || p == "GET /" => match serde_json::from_str::<Value>(&body) {
                    Ok(req) => {
                        let resp = handle_rpc(&st, &req).await;
                        ("200 OK", resp.to_string())
                    }
                    Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
                },
                // ---- worker job queue ----
                p if p.starts_with("POST /jobs") => {
                    if let Ok(v) = serde_json::from_str::<Value>(&body) {
                        st.jobs.lock().unwrap().push_back(v);
                        ("200 OK", r#"{"queued":true}"#.into())
                    } else {
                        ("400 Bad Request", r#"{"error":"bad job json"}"#.into())
                    }
                }
                p if p.starts_with("GET /jobs") => {
                    match st.jobs.lock().unwrap().pop_front() {
                        Some(j) => ("200 OK", j.to_string()),
                        None => ("204 No Content", "".into()),
                    }
                }
                p if p.starts_with("POST /results") => {
                    if let Ok(v) = serde_json::from_str::<Value>(&body) {
                        st.results.lock().unwrap().push(v);
                    }
                    ("200 OK", r#"{"stored":true}"#.into())
                }
                p if p.ends_with("/results/list") => {
                    let r = st.results.lock().unwrap();
                    ("200 OK", serde_json::to_string(&*r).unwrap())
                }
                _ => ("404 Not Found", r#"{"error":"not found"}"#.into()),
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                out.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
