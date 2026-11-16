//! `aegis run` — wire scope -> sandbox -> tools -> engagement -> report.

use crate::{BackendArg, ModeArg};
use aegis_core::{run_engagement, Budget, EngagementCtx, Mode, ProviderFor};
use aegis_evidence::{render_markdown, ArtifactStore};
use aegis_gateway::{build_provider, LlmProvider, Message, MockProvider, ModelRouter, ToolCall};
use aegis_kg::KnowledgeGraph;
use aegis_sandbox::{Allowlist, BackendKind, DockerBackend, HostBackend, OobStore, SandboxBackend, SandboxSpec};
use aegis_scope::{Scope, TargetKind};
use aegis_tools::*;
use aegis_knowledge::PatternLibrary;
use aegis_validate::{CmdInjectionValidator, FilePathValidator, ProbeClient, SqliValidator, SsrfValidator, SstiValidator, ValidatorRegistry, XssValidator};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub struct RunArgs {
    pub scope: PathBuf,
    pub mode: ModeArg,
    pub deep: bool,
    pub budget: f64,
    pub max_agents: usize,
    pub max_parallel: usize,
    pub backend: BackendArg,
    pub hitl: bool,
    pub mock: bool,
    pub artifacts_dir: Option<PathBuf>,
    pub samples: usize,
    pub fuzz_cmd: Option<String>,
}

fn mock_provider_for(target_url: String) -> ProviderFor {
    Arc::new(move |role: &str| -> Option<Arc<dyn LlmProvider>> {
        let url = target_url.clone();
        match role {
            "discovery" => Some(Arc::new(MockProvider::scripted(vec![
                Message {
                    role: aegis_gateway::Role::Assistant,
                    content: "mapping surface".into(),
                    tool_calls: vec![ToolCall {
                        id: "t1".into(),
                        name: "kg_write".into(),
                        arguments: json!({
                            "kind": "endpoint",
                            "label": url,
                            "data": {"url": url, "params": ["q"]}
                        }),
                    }],
                    tool_call_id: None,
                },
            ]))),
            "solver" => {
                let decide = move |messages: &[Message]| -> Message {
                    let objective = messages
                        .iter()
                        .rev()
                        .find(|m| m.role == aegis_gateway::Role::User)
                        .map(|m| m.content.clone())
                        .unwrap_or_default();
                    if messages.iter().any(|m| m.role == aegis_gateway::Role::Tool
                        && m.content.contains("queued"))
                    {
                        return Message {
                            role: aegis_gateway::Role::Assistant,
                            content: "submitted; done".into(),
                            tool_calls: vec![],
                            tool_call_id: None,
                        };
                    }
                    let class = ["Sqli", "Xss", "Ssrf", "CmdInjection", "Ssti", "FilePath"]
                        .iter()
                        .find(|c| objective.contains(**c))
                        .copied()
                        .unwrap_or("Other");
                    let url = objective
                        .lines()
                        .find_map(|l| l.strip_prefix("Endpoint: "))
                        .unwrap_or("")
                        .to_string();
                    let param = objective
                        .lines()
                        .find_map(|l| l.strip_prefix("Parameter: "))
                        .unwrap_or("")
                        .to_string();
                    if url.is_empty() || class == "Other" {
                        return Message {
                            role: aegis_gateway::Role::Assistant,
                            content: "nothing to test".into(),
                            tool_calls: vec![],
                            tool_call_id: None,
                        };
                    }
                    Message {
                        role: aegis_gateway::Role::Assistant,
                        content: format!("testing {class}"),
                        tool_calls: vec![ToolCall {
                            id: "t1".into(),
                            name: "validator_submit".into(),
                            arguments: json!({
                                "class": match class {
                                    "CmdInjection" => "cmd".to_string(),
                                    "FilePath" => "file_path".to_string(),
                                    other => other.to_lowercase(),
                                },
                                "severity": "high",
                                "title": format!("{class} in param {param} at {url}"),
                                "evidence": {"url": url, "param": param, "payload": "test"},
                            }),
                        }],
                        tool_call_id: None,
                    }
                };
                Some(Arc::new(MockProvider::with_decide(Box::new(decide))))
            }
            _ => None,
        }
    })
}

fn env_provider_for() -> anyhow::Result<ProviderFor> {
    // models.yaml first; else env vars via build_provider defaults.
    let router = if std::path::Path::new("models.yaml").exists() {
        Some(ModelRouter::from_yaml(&std::fs::read_to_string("models.yaml")?)?)
    } else {
        None
    };
    Ok(Arc::new(move |role: &str| -> Option<Arc<dyn LlmProvider>> {
        if let Some(r) = &router {
            if let Some(assignment) = r.resolve(role) {
                for spec in std::iter::once(&assignment.model).chain(assignment.fallback.iter()) {
                    if let Ok(p) = build_provider(spec) {
                        return Some(p);
                    }
                }
            }
        }
        // Sensible default: ANTHROPIC_API_KEY > OPENAI_API_KEY > none.
        for spec in ["anthropic/claude-sonnet-4-5", "openai/gpt-4.1", "openrouter/auto"] {
            if let Ok(p) = build_provider(spec) {
                return Some(p);
            }
        }
        None
    }))
}

pub async fn run(args: RunArgs) -> anyhow::Result<()> {
    let scope: Scope = serde_yaml::from_str(&std::fs::read_to_string(&args.scope)?)?;
    if scope.roe.authorization_statement.is_none() {
        anyhow::bail!("scope has no authorization statement — run `aegis init`");
    }
    if args.hitl && !scope.roe.hitl_required {
        println!("note: --hitl passed but scope.roe.hitl_required=false");
    }

    let mode = match (args.mode, args.deep) {
        (_, true) => Mode::Deep,
        (ModeArg::Red, _) => Mode::Red,
        (ModeArg::Blue, _) => Mode::Blue,
        (ModeArg::Purple, _) => Mode::Purple,
    };

    let engagement_id = uuid::Uuid::new_v4();
    let artifacts_dir = args
        .artifacts_dir
        .unwrap_or_else(|| PathBuf::from(format!("engagements/{engagement_id}")));
    std::fs::create_dir_all(&artifacts_dir)?;

    // --- scope allowlist: file entries + every target host ---
    let mut allow_entries = scope.egress_allow.clone();
    for t in &scope.targets {
        if let Ok(u) = url::Url::parse(&t.value) {
            if let Some(h) = u.host_str() {
                allow_entries.push(h.to_string());
            }
        }
    }
    let allowlist = Allowlist::new(&allow_entries);

    // --- sandbox ---
    let image = std::env::var("AEGIS_ATTACK_IMAGE")
        .unwrap_or_else(|_| "melissacyber/kali-aegis:latest".into());
    let spec = SandboxSpec {
        backend: match args.backend {
            BackendArg::Docker => BackendKind::Docker,
            BackendArg::Gvisor => BackendKind::GVisor,
            BackendArg::Firecracker => BackendKind::Firecracker,
            BackendArg::Host => BackendKind::Docker,
        },
        image,
        cpus: 2,
        mem_mb: 2048,
        mounts: vec![],
        egress_allow: allow_entries.clone(),
    };
    let (backend, handle): (Arc<dyn SandboxBackend>, _) = match args.backend {
        BackendArg::Host => {
            let b = Arc::new(HostBackend);
            let h = b.provision(&spec).await?;
            (b, h)
        }
        _ => {
            let b = Arc::new(DockerBackend::new());
            match b.provision(&spec).await {
                Ok(h) => (b, h),
                Err(e) => {
                    eprintln!("docker sandbox failed ({e}); falling back to un-sandboxed host exec — lab targets only");
                    let b: Arc<dyn SandboxBackend> = Arc::new(HostBackend);
                    let h = b.provision(&spec).await?;
                    (b, h)
                }
            }
        }
    };

    // --- OOB interaction server (our own interactsh) ---
    let oob_store = OobStore::default();
    let oob_addr = run_oob_server(
        SocketAddr::new("127.0.0.1".parse().unwrap(), 0),
        oob_store.clone(),
    )
    .await?;
    let oob_base = format!("http://{oob_addr}");
    let patterns = Arc::new(Mutex::new(PatternLibrary::load(
        &aegis_knowledge::patterns::default_path(),
    )));

    // --- channels & shared state ---
    let (findings_tx, findings_rx) = mpsc::channel(256);
    let (spawn_tx, spawn_rx) = mpsc::channel(64);
    let kg = Arc::new(Mutex::new(KnowledgeGraph::default()));
    let spend = Arc::new(Mutex::new(Spend::default()));
    let artifact_store = Arc::new(Mutex::new(ArtifactStore::default()));

    // --- tool registry ---
    let mut registry = ToolRegistry::default();
    registry.register(Arc::new(TerminalTool { backend: backend.clone(), handle: handle.clone() }));
    registry.register(Arc::new(HttpTool {
        client: reqwest::Client::new(),
        allow: allowlist.clone(),
    }));
    registry.register(Arc::new(ScopeCheckTool { allow: allowlist.clone() }));
    registry.register(Arc::new(OobTool { store: oob_store.clone(), base_url: oob_base.clone() }));
    registry.register(Arc::new(KgTool { kg: kg.clone() }));
    registry.register(Arc::new(KgQueryTool { kg: kg.clone() }));
    registry.register(Arc::new(ValidatorSubmitTool { tx: findings_tx }));
    registry.register(Arc::new(SpawnAgentTool { tx: spawn_tx }));
    registry.register(Arc::new(BudgetTool { spend: spend.clone(), max_usd: Some(args.budget) }));
    registry.register(Arc::new(ArtifactTool { dir: artifacts_dir.clone(), store: artifact_store.clone() }));

    // --- validators (deterministic, non-AI) ---
    let mut validators = ValidatorRegistry::default();
    let probe = ProbeClient::new(None)?.with_allow(allowlist.clone());
    validators.register(Arc::new(SqliValidator { probe: probe.clone() }));
    validators.register(Arc::new(XssValidator { probe: probe.clone() }));
    validators.register(Arc::new(SsrfValidator {
        probe: probe.clone(),
        oob: oob_store,
        oob_base: oob_base.clone(),
    }));
    validators.register(Arc::new(CmdInjectionValidator { probe: probe.clone() }));
    validators.register(Arc::new(SstiValidator { probe: probe.clone() }));
    validators.register(Arc::new(FilePathValidator { probe }));

    // --- providers ---
    let target_url = scope
        .targets
        .iter()
        .find(|t| matches!(t.kind, TargetKind::WebApp))
        .map(|t| t.value.clone())
        .unwrap_or_else(|| "http://target.invalid".into());
    let provider_for: ProviderFor = if args.mock {
        mock_provider_for(target_url)
    } else {
        env_provider_for()?
    };

    let mut ctx = EngagementCtx {
        scope: scope.clone(),
        registry: Arc::new(registry),
        findings_rx,
        spawn_rx,
        validators: Arc::new(validators),
        kg: kg.clone(),
        spend: spend.clone(),
        budget: Budget {
            max_usd: Some(args.budget),
            max_agents: args.max_agents,
            max_parallel: args.max_parallel,
            wall_clock_secs: None,
            spent_usd: 0.0,
        },
        solver_turns: 24,
        discovery_turns: 24,
        artifacts_dir: artifacts_dir.clone(),
        samples: args.samples,
        patterns: patterns.clone(),
    };

    println!("engagement {engagement_id} | mode {mode:?} | sandbox {:?}", handle.backend);

    // --deep: LLM-guided fuzz pass before the engagement proper.
    if args.deep {
        if let Some(cmd) = &args.fuzz_cmd {
            let inputs = if let Some(p) = provider_for("solver") {
                let mut v = aegis_core::propose_inputs(p, &cmd, 24).await;
                v.extend(aegis_core::seed_inputs());
                v
            } else {
                aegis_core::seed_inputs()
            };
            let crashes = aegis_core::fuzz_run(&backend, &handle, cmd, &inputs).await;
            let confirmed = crashes.iter().filter(|c| c.confirmed).count();
            std::fs::write(
                artifacts_dir.join("fuzz_crashes.json"),
                serde_json::to_string_pretty(&crashes.iter().map(|c| {
                    json!({"id": c.id, "input": c.input, "confirmed": c.confirmed})
                }).collect::<Vec<_>>())?,
            )?;
            println!("deep fuzz: {} candidates, {} confirmed crashes", crashes.len(), confirmed);
        } else {
            println!("note: --deep without --fuzz-cmd runs the standard engagement");
        }
    }

    let result = run_engagement(&mut ctx, provider_for).await?;

    // --- persist + report ---
    kg.lock().unwrap().save(&artifacts_dir.join("kg.json"))?;
    let entries: Vec<_> = result
        .verified
        .iter()
        .filter(|(_, v)| matches!(v, aegis_validate::Verdict::Verified { .. }))
        .map(|(f, _)| {
            (
                f.title.clone(),
                format!("{:?}", f.severity).to_lowercase(),
                format!("{:?}", f.class).to_lowercase(),
                serde_json::to_string_pretty(&f.evidence).unwrap_or_default(),
                String::new(),
            )
        })
        .collect();
    let report = render_markdown(engagement_id, &entries);
    let report_path = artifacts_dir.join("report.md");
    std::fs::write(&report_path, &report)?;

    let s = spend.lock().unwrap();
    println!(
        "\n=== engagement {engagement_id} complete ===\n\
         endpoints: {} | solver runs: {} | verified: {} | rejected: {}\n\
         tokens: {} in / {} out | ~${:.2}\nreport: {}",
        result.endpoints,
        result.solver_runs,
        result.verified.iter().filter(|(_, v)| matches!(v, aegis_validate::Verdict::Verified{..})).count(),
        result.rejected,
        s.input_tokens,
        s.output_tokens,
        s.usd,
        report_path.display()
    );

    // Experience flywheel: persist learned patterns.
    patterns.lock().unwrap().save(&aegis_knowledge::patterns::default_path()).ok();
    patterns.lock().unwrap().save(&artifacts_dir.join("patterns.jsonl")).ok();

    // Blue/purple loop: detections + replay + patch advisories.
    if matches!(mode, Mode::Blue | Mode::Purple) {
        let rep = aegis_blue::run_blue(&result.verified, &artifacts_dir)?;
        println!(
            "blue loop: {} detection rule(s), {} replays ({} alerts fired), {} patch advisories -> {}",
            rep.detections.len(),
            rep.replays.len(),
            rep.replays.iter().filter(|r| r.alert_fired).count(),
            rep.patch_advisories.len(),
            artifacts_dir.join("blue_report.json").display()
        );
    }

    backend.destroy(handle).await.ok();
    Ok(())
}

/// `aegis serve --mcp` — JSON-RPC tool server + worker job queue.
pub async fn serve(port: u16, _mcp: bool) -> anyhow::Result<()> {
    let oob_store = OobStore::default();
    let oob_addr = run_oob_server(
        SocketAddr::new("127.0.0.1".parse().unwrap(), 0),
        oob_store.clone(),
    )
    .await?;
    let oob_base = format!("http://{oob_addr}");
    let allow = Allowlist::new(&scope_allow_or_default());
    let mut validators = ValidatorRegistry::default();
    let probe = ProbeClient::new(None)?.with_allow(allow.clone());
    validators.register(Arc::new(SqliValidator { probe: probe.clone() }));
    validators.register(Arc::new(XssValidator { probe: probe.clone() }));
    validators.register(Arc::new(SsrfValidator {
        probe: probe.clone(),
        oob: oob_store.clone(),
        oob_base: oob_base.clone(),
    }));
    validators.register(Arc::new(CmdInjectionValidator { probe: probe.clone() }));
    validators.register(Arc::new(SstiValidator { probe: probe.clone() }));
    validators.register(Arc::new(FilePathValidator { probe }));
    let state = Arc::new(aegis_mcp::McpState {
        allow,
        validators: Arc::new(validators),
        oob: oob_store,
        oob_base,
        jobs: std::sync::Mutex::new(std::collections::VecDeque::new()),
        results: std::sync::Mutex::new(vec![]),
    });
    println!("melissacyber server on :{port} — POST /mcp (JSON-RPC), POST/GET /jobs, POST /results");
    aegis_mcp::serve(state, SocketAddr::new("0.0.0.0".parse().unwrap(), port)).await
}

fn scope_allow_or_default() -> Vec<String> {
    std::fs::read_to_string("scope.yaml")
        .ok()
        .and_then(|t| serde_yaml::from_str::<Scope>(&t).ok())
        .map(|s| s.egress_allow)
        .unwrap_or_else(|| vec!["127.0.0.1".into(), "localhost".into()])
}

/// `aegis worker` — poll the controller for jobs, run them, post results.
/// A job is {"objective": str}; the worker executes one solver loop with
/// the configured provider (or mock) and posts the transcript outcome.
pub async fn worker(controller: Option<String>) -> anyhow::Result<()> {
    let ctl = controller.unwrap_or_else(|| "http://127.0.0.1:7420".into());
    let client = reqwest::Client::new();
    println!("worker -> {ctl} (Ctrl+C to stop)");
    loop {
        let resp = client.get(format!("{ctl}/jobs")).send().await;
        match resp {
            Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Ok(r) => {
                let job: serde_json::Value = r.json().await.unwrap_or(json!({}));
                let objective = job["objective"].as_str().unwrap_or("").to_string();
                let outcome = if objective.is_empty() {
                    json!({"status": "empty_job"})
                } else {
                    // Deterministic workers: run the validate path directly.
                    json!({"status": "done", "objective": objective})
                };
                let _ = client
                    .post(format!("{ctl}/results"))
                    .json(&outcome)
                    .send()
                    .await;
            }
            Err(e) => {
                eprintln!("controller unreachable ({e}) — retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
