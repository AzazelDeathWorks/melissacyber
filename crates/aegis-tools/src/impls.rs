//! Concrete Tier-A tool implementations.

use crate::spec::{Tool, ToolError, ToolOutput, ToolSpec};
use aegis_evidence::ArtifactStore;
use aegis_kg::{KnowledgeGraph, Node, NodeKind};
use aegis_sandbox::{Allowlist, SandboxBackend, SandboxHandle};
use aegis_validate::{Finding, FindingClass, Severity};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

fn spec(name: &str, desc: &str, schema: Value, roles: &[&str]) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: desc.into(),
        schema,
        roles: roles.iter().map(|s| s.to_string()).collect(),
    }
}

fn out(v: Value) -> Result<ToolOutput, ToolError> {
    Ok(ToolOutput { ok: true, data: v })
}

fn arg_str<'a>(args: &'a Value, k: &str) -> Result<&'a str, ToolError> {
    args[k]
        .as_str()
        .ok_or_else(|| ToolError::Sandbox(format!("missing arg '{k}'")))
}

// ---------- terminal (docker exec inside the attack box) ----------

pub struct TerminalTool {
    pub backend: Arc<dyn SandboxBackend>,
    pub handle: SandboxHandle,
}

#[async_trait::async_trait]
impl Tool for TerminalTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "terminal",
            "Run a shell command inside the isolated attack sandbox. All Kali tools available.",
            json!({"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let cmd = arg_str(&args, "cmd")?;
        self.backend
            .exec(&self.handle, &[cmd])
            .await
            .map(|s| out(json!({"output": s})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

// ---------- http_client (app-layer scope check + proxied reqwest) ----------

pub struct HttpTool {
    pub client: reqwest::Client,
    pub allow: Allowlist,
}

#[async_trait::async_trait]
impl Tool for HttpTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "http_client",
            "Send an HTTP request through the scoped egress proxy. Returns status/headers/body.",
            json!({
                "type":"object","properties":{
                    "method":{"type":"string","default":"GET"},
                    "url":{"type":"string"},
                    "headers":{"type":"object"},
                    "body":{"type":"string"}
                },"required":["url"]
            }),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let url = arg_str(&args, "url")?;
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let host = parsed.host_str().unwrap_or("");
        if !self.allow.allows(host) {
            return Err(ToolError::ScopeViolation(host.into()));
        }
        let method = args["method"].as_str().unwrap_or("GET");
        let mut req = self.client.request(
            method.parse().unwrap_or(reqwest::Method::GET),
            parsed,
        );
        if let Some(h) = args["headers"].as_object() {
            for (k, v) in h {
                if let Some(vs) = v.as_str() {
                    req = req.header(k, vs);
                }
            }
        }
        if let Some(b) = args["body"].as_str() {
            req = req.body(b.to_string());
        }
        let resp = req.send().await.map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or(""))))
            .collect::<serde_json::Map<_, _>>();
        let body = resp.text().await.unwrap_or_default();
        let body = if body.len() > 64 * 1024 {
            format!("{}…[truncated]", &body[..64 * 1024])
        } else {
            body
        };
        out(json!({"status": status, "headers": headers, "body": body}))
    }
}

// ---------- scope_check ----------

pub struct ScopeCheckTool {
    pub allow: Allowlist,
}

#[async_trait::async_trait]
impl Tool for ScopeCheckTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "scope_check",
            "Check whether a host/URL is inside the authorized scope before touching it.",
            json!({"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let t = arg_str(&args, "target")?;
        let host = reqwest::Url::parse(t)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| t.split(':').next().unwrap_or(t).to_string());
        out(json!({"target": host, "in_scope": self.allow.allows(&host)}))
    }
}

// ---------- oob_canary ----------

pub struct OobTool {
    pub store: aegis_sandbox::oob::OobStore,
    pub base_url: String,
}

#[async_trait::async_trait]
impl Tool for OobTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "oob_canary",
            "Mint an out-of-band callback URL, or fetch hits for a token. Use for blind SSRF/XSS/XXE.",
            json!({"type":"object","properties":{
                "action":{"type":"string","enum":["mint","hits"]},
                "token":{"type":"string"}
            },"required":["action"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        match arg_str(&args, "action")? {
            "mint" => {
                let token = uuid::Uuid::new_v4().simple().to_string();
                out(json!({
                    "token": token,
                    "url": format!("{}/{}/cb", self.base_url, token),
                }))
            }
            "hits" => {
                let token = arg_str(&args, "token")?;
                out(json!({"hits": self.store.hits_for(token)}))
            }
            other => Err(ToolError::Sandbox(format!("bad action {other}"))),
        }
    }
}

// ---------- kg_query / kg_write ----------

pub struct KgTool {
    pub kg: Arc<Mutex<KnowledgeGraph>>,
}

#[async_trait::async_trait]
impl Tool for KgTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "kg_write",
            "Record a node in the engagement knowledge graph (asset/endpoint/fact/finding).",
            json!({"type":"object","properties":{
                "kind":{"type":"string","enum":["asset","endpoint","param","tech","fact","finding","evidence","hypothesis"]},
                "label":{"type":"string"},
                "data":{"type":"object"}
            },"required":["kind","label"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let kind = match arg_str(&args, "kind")? {
            "asset" => NodeKind::Asset,
            "endpoint" => NodeKind::Endpoint,
            "param" => NodeKind::Param,
            "tech" => NodeKind::Tech,
            "fact" => NodeKind::Fact,
            "finding" => NodeKind::Finding,
            "evidence" => NodeKind::Evidence,
            _ => NodeKind::Hypothesis,
        };
        let node = Node {
            id: uuid::Uuid::new_v4(),
            kind,
            label: arg_str(&args, "label")?.to_string(),
            data: args["data"].clone(),
            provenance: None,
        };
        let id = self.kg.lock().unwrap().add_node(node);
        out(json!({"node_id": id}))
    }
}

pub struct KgQueryTool {
    pub kg: Arc<Mutex<KnowledgeGraph>>,
}

#[async_trait::async_trait]
impl Tool for KgQueryTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "kg_query",
            "Query the shared engagement knowledge graph (what is known, what was tried).",
            json!({"type":"object","properties":{
                "kind":{"type":"string"},
                "contains":{"type":"string"}
            }}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let kg = self.kg.lock().unwrap();
        let contains = args["contains"].as_str().unwrap_or("").to_lowercase();
        let kind = args["kind"].as_str().unwrap_or("").to_lowercase();
        let hits: Vec<Value> = kg
            .nodes()
            .filter(|n| {
                (kind.is_empty() || format!("{:?}", n.kind).to_lowercase().contains(&kind))
                    && (contains.is_empty()
                        || n.label.to_lowercase().contains(&contains)
                        || n.data.to_string().to_lowercase().contains(&contains))
            })
            .map(|n| json!({"id": n.id, "kind": n.kind, "label": n.label, "data": n.data}))
            .collect();
        out(json!({"count": hits.len(), "nodes": hits}))
    }
}

// ---------- validator_submit ----------

pub struct ValidatorSubmitTool {
    pub tx: mpsc::Sender<Finding>,
}

#[async_trait::async_trait]
impl Tool for ValidatorSubmitTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "validator_submit",
            "Submit a candidate finding for deterministic verification. Only verified findings reach the report.",
            json!({"type":"object","properties":{
                "class":{"type":"string"},
                "severity":{"type":"string","enum":["info","low","medium","high","critical"]},
                "title":{"type":"string"},
                "evidence":{"type":"object"}
            },"required":["class","severity","title","evidence"]}),
            &["solver", "*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let class = match arg_str(&args, "class")? {
            "sqli" => FindingClass::Sqli,
            "nosqli" => FindingClass::Nosqli,
            "cmd" | "cmd_injection" => FindingClass::CmdInjection,
            "ssti" => FindingClass::Ssti,
            "xss" => FindingClass::Xss,
            "ssrf" => FindingClass::Ssrf,
            "authn" => FindingClass::Authn,
            "idor" | "authz" | "authz_idor" => FindingClass::AuthzIdor,
            "jwt" | "session_jwt" => FindingClass::SessionJwt,
            "deser" | "deserialization" => FindingClass::Deserialization,
            "file_path" | "lfi" | "rfi" | "upload" => FindingClass::FilePath,
            "xxe" => FindingClass::Xxe,
            "smuggling" => FindingClass::Smuggling,
            "cors" => FindingClass::Cors,
            "race" => FindingClass::Race,
            "crypto" => FindingClass::Crypto,
            "crash" => FindingClass::Crash,
            _ => FindingClass::Other,
        };
        let severity = match arg_str(&args, "severity")? {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let f = Finding {
            id: uuid::Uuid::new_v4(),
            class,
            severity,
            title: arg_str(&args, "title")?.to_string(),
            evidence: args["evidence"].clone(),
            verified: false,
        };
        let id = f.id;
        self.tx
            .send(f)
            .await
            .map_err(|e| ToolError::Sandbox(e.to_string()))?;
        out(json!({"queued": true, "finding_id": id}))
    }
}

// ---------- spawn_agent ----------

#[derive(Debug, Clone)]
pub struct SpawnRequest {
    pub kind: String,
    pub objective: String,
}

pub struct SpawnAgentTool {
    pub tx: mpsc::Sender<SpawnRequest>,
}

#[async_trait::async_trait]
impl Tool for SpawnAgentTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "spawn_agent",
            "Spawn a short-lived specialist agent for one objective (coordinator/delegators only).",
            json!({"type":"object","properties":{
                "kind":{"type":"string"},
                "objective":{"type":"string"}
            },"required":["kind","objective"]}),
            &["coordinator"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let req = SpawnRequest {
            kind: arg_str(&args, "kind")?.to_string(),
            objective: arg_str(&args, "objective")?.to_string(),
        };
        self.tx
            .send(req)
            .await
            .map_err(|e| ToolError::Sandbox(e.to_string()))?;
        out(json!({"queued": true}))
    }
}

// ---------- budget_status ----------

#[derive(Debug, Default)]
pub struct Spend {
    pub usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub struct BudgetTool {
    pub spend: Arc<Mutex<Spend>>,
    pub max_usd: Option<f64>,
}

#[async_trait::async_trait]
impl Tool for BudgetTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "budget_status",
            "Check remaining engagement budget.",
            json!({"type":"object","properties":{}}),
            &["*"],
        )
    }
    async fn call(&self, _args: Value) -> Result<ToolOutput, ToolError> {
        let s = self.spend.lock().unwrap();
        out(json!({
            "spent_usd": s.usd,
            "max_usd": self.max_usd,
            "input_tokens": s.input_tokens,
            "output_tokens": s.output_tokens,
        }))
    }
}

// ---------- artifact_store ----------

pub struct ArtifactTool {
    pub dir: PathBuf,
    pub store: Arc<Mutex<ArtifactStore>>,
}

#[async_trait::async_trait]
impl Tool for ArtifactTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "artifact_store",
            "Persist evidence (requests, payloads, screenshots-as-text). Content is sha256-hashed.",
            json!({"type":"object","properties":{
                "name":{"type":"string"},
                "kind":{"type":"string"},
                "content":{"type":"string"}
            },"required":["name","content"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let name = arg_str(&args, "name")?;
        if name.contains('/') || name.contains("..") {
            return Err(ToolError::Sandbox("bad artifact name".into()));
        }
        let content = arg_str(&args, "content")?;
        std::fs::create_dir_all(&self.dir).map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let path = self.dir.join(name);
        std::fs::write(&path, content).map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let id = self.store.lock().unwrap().add(
            args["kind"].as_str().unwrap_or("evidence"),
            path.to_string_lossy().to_string(),
            content.as_bytes(),
        );
        out(json!({"artifact_id": id}))
    }
}
