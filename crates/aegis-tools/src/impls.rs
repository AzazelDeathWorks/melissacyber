//! Concrete Tier-A tool implementations.

use crate::registry::ToolRegistry;
use crate::spec::{Tool, ToolError, ToolOutput, ToolSpec};
use aegis_evidence::ArtifactStore;
use aegis_kg::{KnowledgeGraph, Node, NodeKind};
use aegis_sandbox::{Allowlist, RateLimiter, SandboxBackend, SandboxHandle};
use aegis_validate::{Finding, FindingClass, Severity};
use serde_json::{json, Value};
use std::collections::HashMap;
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

/// Cookies captured by auth_login, keyed by host — injected into later
/// http_client requests for the same host (session persistence).
#[derive(Default)]
pub struct SessionStore {
    pub cookies: HashMap<String, String>,
}

pub struct HttpTool {
    /// Build with redirect::Policy::none() — we follow manually so every
    /// hop is re-checked against the egress allowlist (scope fix).
    pub client: reqwest::Client,
    pub allow: Allowlist,
    pub limiter: Option<Arc<RateLimiter>>,
    pub session: Arc<Mutex<SessionStore>>,
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
        let method = args["method"].as_str().unwrap_or("GET").to_string();
        let mut url = parsed;
        let mut body = args["body"].as_str().map(String::from);
        let mut hops = 0;
        let resp = loop {
            if let Some(l) = &self.limiter {
                l.wait().await;
            }
            let mut req = self.client.request(
                method.parse().unwrap_or(reqwest::Method::GET),
                url.clone(),
            );
            if let Some(h) = args["headers"].as_object() {
                for (k, v) in h {
                    if let Some(vs) = v.as_str() {
                        req = req.header(k, vs);
                    }
                }
            }
            // Inject stored session cookies unless caller set Cookie.
            let has_cookie = args["headers"].as_object().map(|h| {
                h.keys().any(|k| k.eq_ignore_ascii_case("cookie"))
            }).unwrap_or(false);
            if !has_cookie {
                if let Some(ck) = self
                    .session
                    .lock()
                    .unwrap()
                    .cookies
                    .get(url.host_str().unwrap_or(""))
                {
                    req = req.header("cookie", ck);
                }
            }
            if let Some(b) = &body {
                req = req.body(b.clone());
            }
            let r = req.send().await.map_err(|e| ToolError::Sandbox(e.to_string()))?;
            if !(300..400).contains(&r.status().as_u16()) || hops >= 6 {
                break r;
            }
            let loc = r
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let next = url
                .join(loc)
                .map_err(|e| ToolError::Sandbox(e.to_string()))?;
            let nhost = next.host_str().unwrap_or("");
            if !self.allow.allows(nhost) {
                return Err(ToolError::ScopeViolation(format!(
                    "redirect to out-of-scope host {nhost}"
                )));
            }
            url = next;
            body = None; // redirects replay as GET
            hops += 1;
        };
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
            "file_path" | "lfi" | "rfi" => FindingClass::FilePath,
            "xxe" => FindingClass::Xxe,
            "smuggling" => FindingClass::Smuggling,
            "cors" => FindingClass::Cors,
            "info_disclosure" | "info-disclosure" | "infodisclosure" | "info" => FindingClass::InfoDisclosure,
            "open_redirect" | "open-redirect" | "redirect" => FindingClass::OpenRedirect,
            "host_header" | "host-header" | "hostheader" => FindingClass::HostHeader,
            "secrets" | "secret" => FindingClass::Secrets,
            "csrf" => FindingClass::Csrf,
            "idor" | "authz" | "authz_idor" => FindingClass::AuthzIdor,
            "file_upload" | "file-upload" | "upload" => FindingClass::FileUpload,
            "deserialization" | "deser" => FindingClass::Deserialization,
            "race" | "race_condition" => FindingClass::Race,
            "business_logic" | "business-logic" | "logic" => FindingClass::BusinessLogic,
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

// ---------- auth_login (session store -> http_client cookies) ----------

pub struct AuthLoginTool {
    pub client: reqwest::Client,
    pub allow: Allowlist,
    pub session: Arc<Mutex<SessionStore>>,
}

#[async_trait::async_trait]
impl Tool for AuthLoginTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "auth_login",
            "Authenticate against a login endpoint and store the session cookies for later requests.",
            json!({"type":"object","properties":{
                "url":{"type":"string"},
                "fields":{"type":"object","description":"form fields e.g. {username,password}"},
                "headers":{"type":"object"}
            },"required":["url","fields"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let url = arg_str(&args, "url")?;
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let host = parsed.host_str().unwrap_or("").to_string();
        if !self.allow.allows(&host) {
            return Err(ToolError::ScopeViolation(host));
        }
        let fields = args["fields"].as_object().cloned().unwrap_or_default();
        let form: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect();
        let mut req = self.client.post(parsed).form(&form);
        if let Some(h) = args["headers"].as_object() {
            for (k, v) in h {
                if let Some(vs) = v.as_str() {
                    req = req.header(k, vs);
                }
            }
        }
        let resp = req.send().await.map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let mut cookies = vec![];
        for v in resp.headers().get_all("set-cookie") {
            if let Ok(s) = v.to_str() {
                if let Some(pair) = s.split(';').next() {
                    cookies.push(pair.to_string());
                }
            }
        }
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let stored = if cookies.is_empty() {
            // Bearer token in JSON body?
            serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| {
                    v["token"].as_str().or_else(|| v["access_token"].as_str()).map(String::from)
                })
                .map(|t| format!("__bearer__={t}"))
        } else {
            Some(cookies.join("; "))
        };
        if let Some(c) = &stored {
            self.session.lock().unwrap().cookies.insert(host.clone(), c.clone());
        }
        out(json!({
            "status": status,
            "cookies_captured": cookies.len(),
            "session_stored": stored.is_some(),
            "body_preview": &body[..body.len().min(2000)],
        }))
    }
}

// ---------- shell (persistent session: cwd + env survive calls) ----------

pub struct ShellState {
    pub cwd: String,
    pub env: HashMap<String, String>,
}

pub struct ShellTool {
    pub backend: Arc<dyn SandboxBackend>,
    pub handle: SandboxHandle,
    pub sessions: Mutex<HashMap<String, ShellState>>,
}

#[async_trait::async_trait]
impl Tool for ShellTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "shell",
            "Persistent interactive shell in the sandbox. cwd and env survive across calls (use session id to keep state; msfconsole-style tools via terminal if needed).",
            json!({"type":"object","properties":{
                "cmd":{"type":"string"},
                "session":{"type":"string","default":"main"}
            },"required":["cmd"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let cmd = arg_str(&args, "cmd")?.to_string();
        let sid = args["session"].as_str().unwrap_or("main").to_string();
        let trimmed = cmd.trim();
        // State-changing builtins + wrapped command computed under the
        // lock; the guard is dropped before the sandbox await (Send).
        enum Act {
            Reply(Value),
            Exec(String),
        }
        let act = {
            let mut sessions = self.sessions.lock().unwrap();
            let st = sessions.entry(sid.clone()).or_insert_with(|| ShellState {
                cwd: "/work".into(),
                env: HashMap::new(),
            });
            if let Some(rest) = trimmed.strip_prefix("cd ") {
                let dir = rest.trim();
                if dir.starts_with('/') {
                    st.cwd = dir.to_string();
                } else {
                    st.cwd = format!("{}/{}", st.cwd.trim_end_matches('/'), dir);
                }
                Act::Reply(json!({"cwd": st.cwd}))
            } else if let Some(rest) = trimmed.strip_prefix("export ") {
                if let Some((k, v)) = rest.trim().split_once('=') {
                    st.env.insert(k.trim().to_string(), v.trim().to_string());
                    Act::Reply(json!({"set": k.trim()}))
                } else {
                    Act::Reply(json!({"error": "bad export"}))
                }
            } else if let Some(rest) = trimmed.strip_prefix("unset ") {
                st.env.remove(rest.trim());
                Act::Reply(json!({"unset": rest.trim()}))
            } else if trimmed == "env" || trimmed == "pwd" {
                Act::Reply(json!({"cwd": st.cwd, "env": st.env}))
            } else {
                let env_prefix = st
                    .env
                    .iter()
                    .map(|(k, v)| format!("{}={} ", k, v.replace('\'', "'\\''")))
                    .collect::<String>();
                Act::Exec(format!("cd '{}' && {}{}", st.cwd, env_prefix, trimmed))
            }
        };
        let wrapped = match act {
            Act::Reply(v) => return out(v),
            Act::Exec(w) => w,
        };
        self.backend
            .exec(&self.handle, &[&wrapped])
            .await
            .map(|o| out(json!({"output": o, "session": sid})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

// ---------- portscan (native TCP connect, scope-checked) ----------

pub struct PortScanTool {
    pub allow: Allowlist,
}

#[async_trait::async_trait]
impl Tool for PortScanTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "portscan",
            "TCP-connect scan of common ports on an in-scope host.",
            json!({"type":"object","properties":{
                "host":{"type":"string"},
                "ports":{"type":"string","description":"comma list; default top 24"}
            },"required":["host"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let host = arg_str(&args, "host")?;
        if !self.allow.allows(host) {
            return Err(ToolError::ScopeViolation(host.into()));
        }
        let ports: Vec<u16> = args["ports"]
            .as_str()
            .map(|s| {
                s.split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995,
                    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
                    9200,
                ]
            });
        let mut open = vec![];
        for p in ports {
            let addr = format!("{host}:{p}");
            if let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_millis(800),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                open.push(p);
            }
        }
        out(json!({"host": host, "open": open}))
    }
}

// ---------- dns_lookup ----------

pub struct DnsLookupTool;

#[async_trait::async_trait]
impl Tool for DnsLookupTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "dns_lookup",
            "Resolve a hostname to its IP addresses.",
            json!({"type":"object","properties":{"host":{"type":"string"}},"required":["host"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let host = arg_str(&args, "host")?;
        let ips: Vec<String> = tokio::net::lookup_host(format!("{host}:0"))
            .await
            .map(|it| it.map(|a| a.ip().to_string()).collect())
            .map_err(|e| ToolError::Sandbox(e.to_string()))?;
        out(json!({"host": host, "ips": ips}))
    }
}

// ---------- web_inspect (lightweight page analysis; no headless) ----------

pub struct WebInspectTool {
    pub client: reqwest::Client,
    pub allow: Allowlist,
}

#[async_trait::async_trait]
impl Tool for WebInspectTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "web_inspect",
            "Fetch a page and extract links, forms (action+inputs), script srcs, comments — surface for endpoint discovery.",
            json!({"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}),
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
        let html = self
            .client
            .get(parsed)
            .send()
            .await
            .map_err(|e| ToolError::Sandbox(e.to_string()))?
            .text()
            .await
            .unwrap_or_default();
        let grab = |attr: &str| -> Vec<String> {
            let mut v = vec![];
            for m in html.match_indices(&format!("{attr}=\"")) {
                let rest = &html[m.0 + attr.len() + 2..];
                if let Some(end) = rest.find('"') {
                    v.push(rest[..end].to_string());
                }
            }
            v
        };
        let mut inputs = vec![];
        for m in html.match_indices("name=\"") {
            let rest = &html[m.0 + 6..];
            if let Some(end) = rest.find('"') {
                inputs.push(rest[..end].to_string());
            }
        }
        out(json!({
            "links": grab("href"),
            "scripts": grab("src"),
            "form_actions": grab("action"),
            "input_names": inputs,
        }))
    }
}

// ---------- file ops (confined to the engagement artifacts dir) ----------

pub struct FileReadTool {
    pub dir: PathBuf,
}
pub struct FileWriteTool {
    pub dir: PathBuf,
}

fn confined(dir: &PathBuf, name: &str) -> Result<PathBuf, ToolError> {
    let p = dir.join(name);
    if name.contains("..") {
        return Err(ToolError::ScopeViolation("path escapes artifacts dir".into()));
    }
    Ok(p)
}

#[async_trait::async_trait]
impl Tool for FileReadTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "file_read",
            "Read a file from the engagement artifacts dir.",
            json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let p = confined(&self.dir, arg_str(&args, "path")?)?;
        std::fs::read_to_string(&p)
            .map(|c| out(json!({"path": p.display().to_string(), "content": c})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

#[async_trait::async_trait]
impl Tool for FileWriteTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "file_write",
            "Write a file into the engagement artifacts dir (notes, payloads, scripts).",
            json!({"type":"object","properties":{
                "path":{"type":"string"},"content":{"type":"string"}
            },"required":["path","content"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let p = confined(&self.dir, arg_str(&args, "path")?)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&p, arg_str(&args, "content")?)
            .map(|_| out(json!({"written": p.display().to_string()})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

// ---------- browser (real headless chrome, scope-checked) ----------

pub struct BrowserTool {
    pub backend: Arc<dyn SandboxBackend>,
    pub handle: SandboxHandle,
    pub allow: Allowlist,
    pub chrome_path: String,
}

#[async_trait::async_trait]
impl Tool for BrowserTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "browser",
            "Render a page in headless Chrome — returns final DOM text after JS executes, plus extracted links/forms/inputs. Use for SPA/JS-rendered apps and DOM-XSS checks.",
            json!({"type":"object","properties":{
                "url":{"type":"string"},
                "wait_ms":{"type":"integer","default":3000}
            },"required":["url"]}),
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
        let wait = args["wait_ms"].as_u64().unwrap_or(3000);
        // --dump-dom prints the post-JS DOM; virtual-time-budget gives the
        // page time to settle. chrome runs inside the sandbox if the image
        // has it, else the host chrome.
        let cmd = format!(
            "{chrome} --headless=new --disable-gpu --no-sandbox --dump-dom \
             --virtual-time-budget={wait} '{url}' 2>/dev/null",
            chrome = self.chrome_path,
            wait = wait,
            url = url.replace('\'', "'\\''"),
        );
        let dom = self
            .backend
            .exec(&self.handle, &[&cmd])
            .await
            .map_err(|e| ToolError::Sandbox(e.to_string()))?;
        let grab = |attr: &str| -> Vec<String> {
            let mut v = vec![];
            for m in dom.match_indices(&format!("{attr}=\"")) {
                let rest = &dom[m.0 + attr.len() + 2..];
                if let Some(end) = rest.find('"') {
                    v.push(rest[..end].to_string());
                }
            }
            v
        };
        let text: String = {
            // crude tag-strip for readable text
            let mut t = String::new();
            let mut in_tag = false;
            for c in dom.chars() {
                match c {
                    '<' => in_tag = true,
                    '>' => in_tag = false,
                    _ if !in_tag => t.push(c),
                    _ => {}
                }
            }
            t.split_whitespace().collect::<Vec<_>>().join(" ")
        };
        out(json!({
            "dom_len": dom.len(),
            "text_preview": &text[..text.len().min(4000)],
            "links": grab("href"),
            "form_actions": grab("action"),
            "scripts": grab("src"),
            "dom_head": &dom[..dom.len().min(2000)],
        }))
    }
}

// ---------- tmux (true interactive sessions inside the sandbox) ----------

pub struct TmuxTool {
    pub backend: Arc<dyn SandboxBackend>,
    pub handle: SandboxHandle,
}

#[async_trait::async_trait]
impl Tool for TmuxTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "tmux",
            "Interactive terminal session (tmux) in the sandbox: run REPLs like msfconsole/sqlmap/python that need real interaction. action=new_session|send|capture|kill.",
            json!({"type":"object","properties":{
                "action":{"type":"string","enum":["new_session","send","capture","kill"]},
                "session":{"type":"string"},
                "keys":{"type":"string","description":"text to type (send)"},
                "lines":{"type":"integer","default":200}
            },"required":["action","session"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let action = arg_str(&args, "action")?;
        let sess = arg_str(&args, "session")?;
        let esc = |s: &str| s.replace('\'', "'\\''");
        let cmd = match action {
            "new_session" => format!(
                "tmux new-session -d -s '{sess}' && tmux capture-pane -t '{sess}' -p",
                sess = esc(sess)
            ),
            "send" => {
                let keys = esc(arg_str(&args, "keys")?);
                format!(
                    "tmux send-keys -t '{sess}' '{keys}' Enter && sleep 0.4 && tmux capture-pane -t '{sess}' -p",
                    sess = esc(sess)
                )
            }
            "capture" => format!(
                "tmux capture-pane -t '{sess}' -p -S -{lines}",
                sess = esc(sess),
                lines = args["lines"].as_u64().unwrap_or(200)
            ),
            "kill" => format!("tmux kill-session -t '{sess}'", sess = esc(sess)),
            a => return Err(ToolError::Sandbox(format!("bad action {a}"))),
        };
        self.backend
            .exec(&self.handle, &[&cmd])
            .await
            .map(|o| out(json!({"output": o})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

// ---------- exploit-craft: gdb debugging + payload mutation ----------

/// Stateful-ish binary debugging via batched GDB commands (pwndbg
/// inside the attack image if present). Breakpoints, regs, mem, stack.
pub struct GdbDebugTool {
    pub backend: Arc<dyn SandboxBackend>,
    pub handle: SandboxHandle,
}

#[async_trait::async_trait]
impl Tool for GdbDebugTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "gdb_debug",
            "Debug a binary in the sandbox with gdb: checksec, disasm, break/run, registers, memory/stack reads. Batch commands per call.",
            json!({"type":"object","properties":{
                "binary":{"type":"string"},
                "commands":{"type":"array","items":{"type":"string"},"description":"gdb commands e.g. ['checksec','b *main','run < input','info registers']"},
                "stdin_file":{"type":"string"}
            },"required":["binary","commands"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let bin = arg_str(&args, "binary")?;
        let cmds = args["commands"]
            .as_array()
            .ok_or_else(|| ToolError::Sandbox("commands must be array".into()))?
            .iter()
            .filter_map(|c| c.as_str().map(String::from))
            .collect::<Vec<_>>();
        let script = cmds.join("\\n").replace('\'', "'\\''");
        let cmd = format!(
            "echo '{script}' > /tmp/gdb-cmds && gdb -q -batch -x /tmp/gdb-cmds '{bin}' 2>&1 | tail -150",
            script = script,
            bin = bin.replace('\'', "'\\''"),
        );
        self.backend
            .exec(&self.handle, &[&cmd])
            .await
            .map(|o| out(json!({"output": o})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

/// Deterministic payload mutator — encodings, case tricks, comment
/// injection, unicode, chunked. Pure code; the model gets variants to try.
pub struct PayloadMutatorTool;

#[async_trait::async_trait]
impl Tool for PayloadMutatorTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "payload_mutator",
            "Generate mutated variants of a payload: url/base64/hex/entity encodings, case alternation, comment splitting, double-encoding, null bytes.",
            json!({"type":"object","properties":{
                "payload":{"type":"string"},
                "family":{"type":"string","enum":["encode","split","case","all"],"default":"all"}
            },"required":["payload"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let p = arg_str(&args, "payload")?;
        let mut out_v: Vec<String> = vec![p.to_string()];
        out_v.push(urlencoding(p));
        out_v.push(urlencoding(&urlencoding(p)));
        out_v.push(base64ish(p));
        out_v.push(p.chars().map(|c| format!("%{:02x}", c as u32)).collect::<String>());
        out_v.push(case_alt(p));
        out_v.push(p.chars().map(|c| format!("&#x{:x};", c as u32)).collect::<String>());
        let p = p.to_string();
        // comment-split for sqli/xss bypass
        if p.contains(' ') {
            out_v.push(p.replace(' ', "/**/"));
            out_v.push(p.replace(' ', "%09"));
            out_v.push(p.replace(' ', "%0a"));
        }
        out_v.push(format!("%00{p}"));
        out_v.push(format!("{p}%00"));
        let dedup: Vec<String> = out_v
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        out(json!({"variants": dedup}))
    }
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02x}")
            }
        })
        .collect()
}
fn base64ish(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in s.as_bytes().chunks(3) {
        let b = [c.first().copied().unwrap_or(0), c.get(1).copied().unwrap_or(0), c.get(2).copied().unwrap_or(0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for (sh, ok) in [(18, true), (12, c.len() > 1), (6, c.len() > 2), (0, c.len() > 3)] {
            if ok {
                o.push(T[((n >> sh) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}
fn case_alt(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| if i % 2 == 0 { c.to_ascii_lowercase() } else { c.to_ascii_uppercase() })
        .collect()
}

// ---------- meta-tooling: agent-authored tools, policy-checked ----------

/// An agent writes a small declarative tool (name + shell template); the
/// broker registers it for this session after schema checks. Commands run
/// in the sandbox like everything else.
pub struct DefineTool {
    pub registry: Arc<ToolRegistry>,
    pub backend: Arc<dyn SandboxBackend>,
    pub handle: SandboxHandle,
}

#[async_trait::async_trait]
impl Tool for DefineTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "define_tool",
            "Author a new tool for this session: {name, description, command_template}. The template runs in the sandbox with {arg} placeholders substituted. Subject to policy review.",
            json!({"type":"object","properties":{
                "name":{"type":"string"},
                "description":{"type":"string"},
                "command_template":{"type":"string"},
                "arg_names":{"type":"array","items":{"type":"string"}}
            },"required":["name","description","command_template"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let name = arg_str(&args, "name")?;
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || name.len() > 40 {
            return Err(ToolError::Sandbox("bad tool name".into()));
        }
        let desc = arg_str(&args, "description")?;
        let tpl = arg_str(&args, "command_template")?;
        // Policy review: no destructive primitives, no network out except
        // through normal channels (curl allowed — egress proxy enforces scope).
        let banned = ["rm -rf /", ":(){", "mkfs", "dd if=", "shutdown", "reboot", "kill -9 -1", "> /dev/sd"];
        if banned.iter().any(|b| tpl.contains(b)) {
            return Err(ToolError::Policy("template rejected by policy review".into()));
        }
        let arg_names = args["arg_names"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>())
            .unwrap_or_default();
        let tool = DynTool {
            spec: ToolSpec {
                name: name.to_string(),
                description: format!("[agent-authored] {desc}"),
                schema: json!({"type":"object","properties":{}}),
                roles: vec!["*".into()],
            },
            template: tpl.to_string(),
            arg_names,
            backend: self.backend.clone(),
            handle: self.handle.clone(),
        };
        self.registry.register(Arc::new(tool));
        out(json!({"registered": name, "note": "tool available for the rest of this session"}))
    }
}

struct DynTool {
    spec: ToolSpec,
    template: String,
    arg_names: Vec<String>,
    backend: Arc<dyn SandboxBackend>,
    handle: SandboxHandle,
}

#[async_trait::async_trait]
impl Tool for DynTool {
    fn spec(&self) -> ToolSpec {
        self.spec.clone()
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let mut cmd = self.template.clone();
        for n in &self.arg_names {
            let v = args[n].as_str().unwrap_or("");
            cmd = cmd.replace(&format!("{{{n}}}"), &format!("'{}'", v.replace('\'', "'\\''")));
        }
        self.backend
            .exec(&self.handle, &[&cmd])
            .await
            .map(|o| out(json!({"output": o})).unwrap())
            .map_err(|e| ToolError::Sandbox(e.to_string()))
    }
}

// ---------- browser steering (CDP-driven headless chrome) ----------

/// Real browser control: the agent drives a throwaway headless Chrome via
/// CDP — navigate, click, type, evaluate JS, scroll, screenshot. Unlike the
/// `browser` tool (one-shot DOM render), a session carries a step list
/// executed in order inside ONE live page, enabling login flows, CSRF
/// token submission, and DOM-XSS proof.
pub struct BrowserSteerTool {
    pub allow: Allowlist,
    pub chrome_path: String,
    /// Where screenshots land (engagement artifacts dir).
    pub shots_dir: std::path::PathBuf,
}

fn jsq(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

#[async_trait::async_trait]
impl Tool for BrowserSteerTool {
    fn spec(&self) -> ToolSpec {
        spec(
            "browser_steer",
            "Drive a live headless browser step-by-step (CDP): navigate a url, then click selectors, type into fields, run JS, scroll, screenshot. Returns final DOM+URL and per-step results. Use for login flows, multi-step forms, DOM-XSS.",
            json!({"type":"object","properties":{
                "url":{"type":"string"},
                "wait_ms":{"type":"integer","default":3000},
                "steps":{"type":"array","items":{"type":"object"},
                    "description":"ordered actions: {click:sel}|{type:{selector,text,enter}}|{eval:js}|{wait_ms:n}|{scroll:n}|{shot:name}"}
            },"required":["url"]}),
            &["*"],
        )
    }
    async fn call(&self, args: Value) -> Result<ToolOutput, ToolError> {
        let url = arg_str(&args, "url")?;
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        if !self.allow.allows(&host) {
            return Err(ToolError::ScopeViolation(host));
        }
        let wait = args["wait_ms"].as_u64().unwrap_or(3000);
        let mut cdp = crate::cdp::Cdp::launch(&self.chrome_path)
            .await
            .map_err(ToolError::Sandbox)?;
        let run = self.run_steps(&mut cdp, url, wait, &args).await;
        let _ = cdp.close().await;
        let (dom, final_url, results) = run?;
        let text: String = {
            let mut t = String::new();
            let mut in_tag = false;
            for c in dom.chars() {
                match c {
                    '<' => in_tag = true,
                    '>' => in_tag = false,
                    _ if !in_tag => t.push(c),
                    _ => {}
                }
            }
            t.split_whitespace().collect::<Vec<_>>().join(" ")
        };
        // scope-check where the browser ended up
        let end_host = reqwest::Url::parse(&final_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        out(json!({
            "final_url": final_url,
            "in_scope": self.allow.allows(&end_host),
            "steps": results,
            "dom_len": dom.len(),
            "text_preview": &text[..text.len().min(4000)],
            "dom_head": &dom[..dom.len().min(2000)],
        }))
    }
}

impl BrowserSteerTool {
    async fn run_steps(
        &self,
        cdp: &mut crate::cdp::Cdp,
        url: &str,
        wait: u64,
        args: &Value,
    ) -> Result<(String, String, Vec<Value>), ToolError> {
        cdp.navigate(url, wait).await.map_err(ToolError::Sandbox)?;
        let mut results = vec![];
        if let Some(steps) = args["steps"].as_array() {
            for step in steps {
                let r: Value = if let Some(sel) = step["click"].as_str() {
                    let v = cdp
                        .eval(&format!(
                            "(()=>{{const el=document.querySelector({});if(!el)return 'MISSING';el.scrollIntoView({{block:'center'}});el.click();return 'clicked'}})()",
                            jsq(sel)
                        ))
                        .await;
                    json!({"click": sel, "result": v.map_err(|e| serde_json::Value::String(e)).unwrap_or_else(|v| v)})
                } else if let Some(t) = step.get("type") {
                    let sel = t["selector"].as_str().unwrap_or("");
                    let text = t["text"].as_str().unwrap_or("");
                    let enter = t["enter"].as_bool().unwrap_or(false);
                    let submit = if enter {
                        ";const f=el.closest('form');if(f)f.requestSubmit();"
                    } else {
                        ""
                    };
                    let v = cdp
                        .eval(&format!(
                            "(()=>{{const el=document.querySelector({});if(!el)return 'MISSING';el.focus();el.value={};el.dispatchEvent(new Event('input',{{bubbles:true}}));el.dispatchEvent(new Event('change',{{bubbles:true}})){};return 'typed'}})()",
                            jsq(sel), jsq(text), submit
                        ))
                        .await;
                    json!({"type": sel, "result": v.map_err(|e| serde_json::Value::String(e)).unwrap_or_else(|v| v)})
                } else if let Some(js) = step["eval"].as_str() {
                    let v = cdp.eval(js).await;
                    json!({"eval": js, "result": v.map_err(|e| serde_json::Value::String(e)).unwrap_or_else(|v| v)})
                } else if let Some(ms) = step["wait_ms"].as_u64() {
                    tokio::time::sleep(std::time::Duration::from_millis(ms.min(30_000))).await;
                    json!({"wait_ms": ms, "result": "ok"})
                } else if let Some(px) = step["scroll"].as_i64() {
                    let v = cdp.eval(&format!("window.scrollBy(0,{px})")).await;
                    json!({"scroll": px, "result": v.map_err(|e| serde_json::Value::String(e)).unwrap_or_else(|v| v)})
                } else if let Some(name) = step["shot"].as_str() {
                    match cdp.screenshot().await {
                        Ok(png) => {
                            let safe: String = name
                                .chars()
                                .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
                                .collect();
                            std::fs::create_dir_all(&self.shots_dir).ok();
                            let path = self.shots_dir.join(format!("{safe}.png"));
                            let ok = std::fs::write(&path, png).is_ok();
                            json!({"shot": name, "saved": ok, "path": path.to_string_lossy()})
                        }
                        Err(e) => json!({"shot": name, "error": e}),
                    }
                } else {
                    json!({"error": "unknown step", "step": step})
                };
                results.push(r);
            }
        }
        let (dom, final_url) = cdp.snapshot().await.map_err(ToolError::Sandbox)?;
        Ok((dom, final_url, results))
    }
}
