//! Policy broker — the single pipe every tool call flows through:
//!
//! tool_call → kill-switch check → risk classify → approval gate →
//! secret-slot injection → dispatch → hash-chained audit.
//!
//! The model never sees credentials (`$slot:NAME` resolved here), and no
//! action above the approved risk class runs — prompt can't bypass it.

use crate::spec::{Tool, ToolError, ToolOutput};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionClass {
    Passive = 0,
    Active,
    ExploitPoc,
    ExploitDestructive,
    PostExploit,
    Admin,
}

impl ActionClass {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
            Self::ExploitPoc => "exploit-poc",
            Self::ExploitDestructive => "exploit-destructive",
            Self::PostExploit => "post-exploit",
            Self::Admin => "admin",
        }
    }
}

/// Risk class of each tool — name-based, deterministic.
pub fn classify(tool_name: &str) -> ActionClass {
    match tool_name {
        "kg_read" | "kg_write" | "file_read" | "dns_lookup" | "report"
        | "web_inspect" | "browser" => ActionClass::Passive,
        "http_client" | "oob_canary" | "portscan" | "auth_login" | "file_write" => {
            ActionClass::Active
        }
        "terminal" | "shell" | "tmux" | "define_tool" | "submit_finding" => {
            ActionClass::ExploitPoc
        }
        "spawn_agent" | "gdb_debug" => ActionClass::PostExploit,
        _ => ActionClass::Active,
    }
}

/// Circuit breaker — pauses dispatch when the target degrades
/// (consecutive transport failures), then half-opens.
pub struct HealthMonitor {
    consecutive_failures: AtomicU64,
    open_until_ms: AtomicU64,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            consecutive_failures: AtomicU64::new(0),
            open_until_ms: AtomicU64::new(0),
        }
    }
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    pub fn circuit_open(&self) -> bool {
        Self::now_ms() < self.open_until_ms.load(Ordering::SeqCst)
    }
    pub fn record_failure(&self) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if n >= 8 {
            // trip: cool down for ~30s
            self.open_until_ms
                .store(Self::now_ms() + 30_000, Ordering::SeqCst);
            self.consecutive_failures.store(0, Ordering::SeqCst);
            tracing::warn!("health monitor: circuit open — target degraded, pausing 30s");
        }
    }
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }
}

pub struct PolicyBroker {
    /// Highest auto-approved class; above needs explicit scope opt-in.
    pub max_auto_class: ActionClass,
    /// Destructive/post-exploit allowed via scope flags (allow_dos etc).
    pub allow_destructive: bool,
    /// kill switch — Phase1: new actions refuse instantly.
    pub kill: Arc<AtomicBool>,
    /// secret slots: model writes "$slot:NAME", broker resolves.
    secrets: HashMap<String, String>,
    /// hash-chained audit log path (audit.jsonl).
    audit_path: PathBuf,
    prev_hash: Mutex<String>,
    pub health: HealthMonitor,
    /// approval-channel error text keeps the model informed.
    pub approvals_note: String,
}

impl PolicyBroker {
    pub fn new(
        max_auto_class: ActionClass,
        allow_destructive: bool,
        audit_path: PathBuf,
        kill: Arc<AtomicBool>,
    ) -> Self {
        let secrets = std::env::vars()
            .filter(|(k, _)| k.starts_with("AEGIS_SLOT_"))
            .map(|(k, v)| (k["AEGIS_SLOT_".len()..].to_string(), v))
            .collect();
        Self {
            max_auto_class,
            allow_destructive,
            kill,
            secrets,
            audit_path,
            prev_hash: Mutex::new("genesis".into()),
            health: HealthMonitor::new(),
            approvals_note: "action blocked by policy gate".into(),
        }
    }

    /// Inject "$slot:NAME" values into args recursively — model never sees
    /// the secret, the tool receives the real value.
    fn resolve_slots(&self, v: &mut Value) {
        match v {
            Value::String(s) => {
                if let Some(name) = s.strip_prefix("$slot:") {
                    if let Some(real) = self.secrets.get(name) {
                        *s = real.clone();
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.resolve_slots(x)),
            Value::Object(o) => o.values_mut().for_each(|x| self.resolve_slots(x)),
            _ => {}
        }
    }

    fn audit(&self, role: &str, tool: &str, class: ActionClass, verdict: &str) {
        use std::io::Write;
        let entry = serde_json::json!({
            "ts": HealthMonitor::now_ms(),
            "role": role, "tool": tool,
            "class": class.name(), "verdict": verdict,
        });
        let body = entry.to_string();
        let mut prev = self.prev_hash.lock().unwrap();
        let prev_hash = prev.clone();
        let chained = format!("{}|{}", prev_hash, body);
        let hash = format!("{:x}", {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            chained.hash(&mut h);
            h.finish()
        });
        *prev = hash.clone();
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
        {
            let _ = writeln!(
                f,
                "{}",
                serde_json::json!({"seq_hash": hash, "prev_hash": prev_hash, "entry": entry})
            );
        }
    }

    /// The one dispatch path. Returns tool error for policy denials so the
    /// agent learns the gate exists rather than the call silently failing.
    pub async fn dispatch(
        &self,
        tool: &Arc<dyn Tool>,
        mut args: Value,
        role: &str,
    ) -> Result<ToolOutput, ToolError> {
        let class = classify(&tool.spec().name);

        // Phase-1 kill switch: refuse every new action immediately.
        if self.kill.load(Ordering::SeqCst) {
            self.audit(role, &tool.spec().name, class, "killed");
            return Err(ToolError::Policy(self.approvals_note.clone() + " (kill switch engaged)"));
        }
        // Circuit breaker.
        if self.health.circuit_open() {
            self.audit(role, &tool.spec().name, class, "circuit_open");
            return Err(ToolError::Policy(
                "health monitor: target degraded, retry later".into(),
            ));
        }
        // Approval gate: above auto class needs the destructive opt-in.
        if class > self.max_auto_class && !(self.allow_destructive && class <= ActionClass::PostExploit) {
            self.audit(role, &tool.spec().name, class, "denied");
            return Err(ToolError::Policy(format!(
                "action class '{}' requires approval (set scope allow flags)",
                class.name()
            )));
        }

        self.resolve_slots(&mut args);
        let result = tool.call(args).await;
        match &result {
            Ok(_) => {
                self.health.record_success();
                self.audit(role, &tool.spec().name, class, "ok");
            }
            Err(ToolError::Sandbox(_)) | Err(ToolError::Net(_)) => {
                self.health.record_failure();
                self.audit(role, &tool.spec().name, class, "tool_error");
            }
            Err(_) => {
                self.audit(role, &tool.spec().name, class, "tool_error");
            }
        }
        result
    }
}
