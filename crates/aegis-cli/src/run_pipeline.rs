//! `aegis run` — wire scope -> sandbox -> tools -> engagement -> report.

use crate::{BackendArg, ModeArg};
use aegis_core::{run_engagement, Budget, EngagementCtx, Mode, ProviderFor};
use aegis_evidence::{render_markdown, ArtifactStore};
use aegis_gateway::{build_provider, LlmProvider, Message, MockProvider, ModelRouter, ToolCall};
use aegis_kg::KnowledgeGraph;
use aegis_sandbox::{Allowlist, BackendKind, DockerBackend, HostBackend, OobStore, RateLimiter, SandboxBackend, SandboxSpec};
use aegis_scope::{Scope, TargetKind};
use aegis_tools::*;
use aegis_knowledge::PatternLibrary;
use aegis_validate::{
    CorsValidator, InfoDisclosureValidator, JwtValidator, ReplayValidator, CmdInjectionValidator,
    FilePathValidator, ProbeClient, SqliValidator, SsrfValidator, SstiValidator,
    ValidatorRegistry, XxeValidator, XssValidator};
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
    pub timeout_secs: u64,
    pub resume: bool,
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
    if scope.roe.hitl_required && !args.hitl {
        anyhow::bail!(
            "scope.roe.hitl_required=true — re-run with --hitl and an operator confirming gates"
        );
    }
    if let Some((start, end)) = &scope.roe.window_utc {
        // HH:MM UTC without a chrono dep.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now = format!("{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60);
        let in_window = if start <= end {
            now.as_str() >= start.as_str() && now.as_str() <= end.as_str()
        } else {
            // overnight window e.g. 22:00-06:00
            now.as_str() >= start.as_str() || now.as_str() <= end.as_str()
        };
        if !in_window {
            anyhow::bail!(
                "outside authorized window (roe.window_utc {start}–{end} UTC, now {now} UTC)"
            );
        }
    }
    if !scope.roe.allow_dos {
        // DoS-class sweeps stay off; validators only send a handful of
        // requests each, so the cap below is the operative control.
    }
    // RoE rate limit — shared by probes AND the http_client tool so the
    // cap can't be sidestepped by picking a different code path.
    let limiter: Option<Arc<RateLimiter>> = if scope.roe.rate_limit_rps > 0 {
        Some(Arc::new(RateLimiter::per_second(scope.roe.rate_limit_rps as f64)))
    } else {
        None
    };
    if let Some(l) = &limiter {
        println!("roe rate limit: {} req/s enforced", scope.roe.rate_limit_rps);
        let _ = l;
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
                    // Host exec bypasses the network-level scope proxy —
                    // only permit it for local lab targets.
                    let all_local = scope.targets.iter().all(|t| {
                        url::Url::parse(&t.value)
                            .map(|u| matches!(u.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]")))
                            .unwrap_or(true)
                    });
                    if !all_local {
                        anyhow::bail!(
                            "docker sandbox failed ({e}) and targets are not local — refusing un-sandboxed host exec (scope guarantee)"
                        );
                    }
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
    let oob_bind: SocketAddr = std::env::var("AEGIS_OOB_BIND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| SocketAddr::new("127.0.0.1".parse().unwrap(), 0));
    let oob_addr = run_oob_server(oob_bind, oob_store.clone()).await?;
    // For remote targets set AEGIS_OOB_PUBLIC to the reachable URL
    // (e.g. a tunnel); otherwise we advertise the bound address.
    // DNS listener for blind-exfil channels (target may lack HTTP egress).
    let dns_bind: SocketAddr = std::env::var("AEGIS_OOB_DNS_BIND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| SocketAddr::new("127.0.0.1".parse().unwrap(), 0));
    let _ = aegis_sandbox::run_oob_dns(dns_bind, oob_store.clone())
        .await
        .map(|a| println!("oob dns listener on {a}"));
    let oob_base = std::env::var("AEGIS_OOB_PUBLIC")
        .unwrap_or_else(|_| format!("http://{oob_addr}"));
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
    let session_store = Arc::new(Mutex::new(impls::SessionStore::default()));
    registry.register(Arc::new(TerminalTool { backend: backend.clone(), handle: handle.clone() }));
    registry.register(Arc::new(impls::ShellTool {
        backend: backend.clone(),
        handle: handle.clone(),
        sessions: Mutex::new(std::collections::HashMap::new()),
    }));
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    registry.register(Arc::new(HttpTool {
        client: http_client.clone(),
        allow: allowlist.clone(),
        limiter: limiter.clone(),
        session: session_store.clone(),
    }));
    registry.register(Arc::new(impls::AuthLoginTool {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
        allow: allowlist.clone(),
        session: session_store,
    }));
    registry.register(Arc::new(impls::PortScanTool { allow: allowlist.clone() }));
    registry.register(Arc::new(impls::DnsLookupTool));
    registry.register(Arc::new(impls::WebInspectTool {
        client: http_client,
        allow: allowlist.clone(),
    }));
    registry.register(Arc::new(impls::FileReadTool { dir: artifacts_dir.clone() }));
    registry.register(Arc::new(impls::FileWriteTool { dir: artifacts_dir.clone() }));
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
    let mut probe = ProbeClient::new(None)?.with_allow(allowlist.clone());
    if let Some(l) = &limiter {
        probe = probe.with_limiter(l.clone());
    }
    validators.register(Arc::new(SqliValidator { probe: probe.clone() }));
    validators.register(Arc::new(XssValidator { probe: probe.clone() }));
    validators.register(Arc::new(SsrfValidator {
        probe: probe.clone(),
        oob: oob_store,
        oob_base: oob_base.clone(),
    }));
    validators.register(Arc::new(CmdInjectionValidator { probe: probe.clone() }));
    validators.register(Arc::new(SstiValidator { probe: probe.clone() }));
    validators.register(Arc::new(FilePathValidator { probe: probe.clone() }));
    validators.register(Arc::new(ReplayValidator { probe: probe.clone() }));
    validators.register(Arc::new(CorsValidator { probe: probe.clone() }));
    validators.register(Arc::new(JwtValidator { probe: probe.clone() }));
    validators.register(Arc::new(XxeValidator { probe: probe.clone() }));
    validators.register(Arc::new(InfoDisclosureValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::OpenRedirectValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::HostHeaderValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::SecretsValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::CsrfValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::IdorValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::FileUploadValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::DeserValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::RaceValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::BusinessLogicValidator { probe }));

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
    // Per-role USD prices from models.yaml (cost_in/cost_out), if set.
    let mut prices: std::collections::HashMap<String, (f64, f64)> =
        std::collections::HashMap::new();
    if std::path::Path::new("models.yaml").exists() {
        if let Ok(router) =
            ModelRouter::from_yaml(&std::fs::read_to_string("models.yaml")?)
        {
            for role in ["solver", "discovery", "critic", "default"] {
                if let Some(p) = router.price_for(role) {
                    prices.insert(role.to_string(), p);
                }
            }
        }
    }

    let kill = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let policy = Arc::new(aegis_tools::broker::PolicyBroker::new(
        if scope.roe.allow_dos {
            aegis_tools::broker::ActionClass::PostExploit
        } else {
            aegis_tools::broker::ActionClass::ExploitPoc
        },
        scope.roe.allow_dos,
        artifacts_dir.join("audit.jsonl"),
        kill.clone(),
    ));
    let kill_for_signal = kill.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        kill_for_signal.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::warn!("kill switch engaged — refusing new actions");
    });
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
        prices,
        traces_dir: artifacts_dir.join("traces"),
        sweeps: true,
        skip_discovery: args.resume,
        resume_keys: Arc::new(std::sync::Mutex::new(load_resume_keys(&artifacts_dir))),
        packs_dir: std::path::PathBuf::from("packs"),
        policy: Some(policy.clone()),
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

    let result = if args.timeout_secs > 0 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(args.timeout_secs),
            run_engagement(&mut ctx, provider_for),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                eprintln!("engagement hit --timeout-secs {} — sandbox cleaned up, partial artifacts kept", args.timeout_secs);
                backend.destroy(handle).await.ok();
                anyhow::bail!("timeout");
            }
        }
    } else {
        run_engagement(&mut ctx, provider_for).await?
    };

    // --- persist + report ---
    kg.lock().unwrap().save(&artifacts_dir.join("kg.json"))?;
    let entries: Vec<_> = result
        .verified
        .iter()
        .filter(|(_, v)| matches!(v, aegis_validate::Verdict::Verified { .. }))
        .map(|(f, v)| {
            (
                f.title.clone(),
                format!("{:?}", f.severity).to_lowercase(),
                format!("{:?}", f.class).to_lowercase(),
                serde_json::to_string_pretty(&f.evidence).unwrap_or_default(),
                match v {
                    aegis_validate::Verdict::Verified { reproduction } => reproduction.clone(),
                    _ => String::new(),
                },
            )
        })
        .collect();
    let mut report = render_markdown(engagement_id, &entries);
    if !result.rejected_list.is_empty() {
        report.push_str("

## Attempted but unproven\n\n");
        for (title, reason) in &result.rejected_list {
            report.push_str(&format!("- **{title}** — {reason}\n"));
        }
    }
    let report_path = artifacts_dir.join("report.md");
    std::fs::write(&report_path, &report)?;
    // SARIF for GitHub code-scanning / other SAST dashboards.
    let rules: Vec<serde_json::Value> = result
        .verified
        .iter()
        .filter(|(_, v)| matches!(v, aegis_validate::Verdict::Verified { .. }))
        .map(|(f, _)| json!({"id": format!("{:?}", f.class), "name": f.title}))
        .collect();
    let sarif_results: Vec<serde_json::Value> = result
        .verified
        .iter()
        .filter(|(_, v)| matches!(v, aegis_validate::Verdict::Verified { .. }))
        .map(|(f, v)| {
            let repro = match v {
                aegis_validate::Verdict::Verified { reproduction } => reproduction.clone(),
                _ => String::new(),
            };
            json!({
                "ruleId": format!("{:?}", f.class),
                "level": match f.severity {
                    aegis_validate::Severity::Critical => "error",
                    aegis_validate::Severity::High => "error",
                    aegis_validate::Severity::Medium => "warning",
                    _ => "note",
                },
                "message": {"text": format!("{} — {}", f.title, repro)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.evidence["url"].as_str().unwrap_or("target")}}}],
            })
        })
        .collect();
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "melissacyber", "version": env!("CARGO_PKG_VERSION"), "rules": rules}},
            "results": sarif_results,
        }],
    });
    std::fs::write(
        artifacts_dir.join("report.sarif"),
        serde_json::to_string_pretty(&sarif)?,
    )?;

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
/// Binds localhost by default; non-local bind requires --token.
pub async fn serve(port: u16, _mcp: bool, bind: &str, token: Option<String>) -> anyhow::Result<()> {
    let bind_ip: std::net::IpAddr = bind.parse()?;
    let local = bind_ip.is_loopback();
    if !local && token.is_none() {
        anyhow::bail!(
            "binding {bind} without --token would expose unauthenticated pentest tools — refused"
        );
    }
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
    validators.register(Arc::new(FilePathValidator { probe: probe.clone() }));
    validators.register(Arc::new(ReplayValidator { probe: probe.clone() }));
    validators.register(Arc::new(CorsValidator { probe: probe.clone() }));
    validators.register(Arc::new(JwtValidator { probe: probe.clone() }));
    validators.register(Arc::new(XxeValidator { probe: probe.clone() }));
    validators.register(Arc::new(InfoDisclosureValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::OpenRedirectValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::HostHeaderValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::SecretsValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::CsrfValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::IdorValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::FileUploadValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::DeserValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::RaceValidator { probe: probe.clone() }));
    validators.register(Arc::new(aegis_validate::BusinessLogicValidator { probe }));
    let state = Arc::new(aegis_mcp::McpState {
        allow,
        validators: Arc::new(validators),
        oob: oob_store,
        oob_base,
        jobs: std::sync::Mutex::new(std::collections::VecDeque::new()),
        results: std::sync::Mutex::new(vec![]),
        token,
    });
    println!("melissacyber server on {bind}:{port} — POST /mcp (JSON-RPC), POST/GET /jobs, POST /results");
    aegis_mcp::serve(state, SocketAddr::new(bind_ip, port)).await
}

fn scope_allow_or_default() -> Vec<String> {
    std::fs::read_to_string("scope.yaml")
        .ok()
        .and_then(|t| serde_yaml::from_str::<Scope>(&t).ok())
        .map(|s| s.egress_allow)
        .unwrap_or_else(|| vec!["127.0.0.1".into(), "localhost".into()])
}

/// `aegis worker` — poll the controller, run each job as a real solver
/// loop (provider + tools + validators), post verdicts back.
/// Job: {"objective": str, "allow": ["host",...], "turns": n}
pub async fn worker(controller: Option<String>) -> anyhow::Result<()> {
    let ctl = controller.unwrap_or_else(|| "http://127.0.0.1:7420".into());
    let client = reqwest::Client::new();
    let provider_for = env_provider_for().ok();
    if provider_for.is_none() {
        eprintln!("warning: no provider configured — worker will report errors");
    }
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
                    match run_worker_job(&job, &objective, provider_for.as_ref()).await {
                        Ok(v) => v,
                        Err(e) => json!({"status": "error", "error": e.to_string()}),
                    }
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

/// Execute one queued job end-to-end: solver loop -> findings ->
/// deterministic validation -> verdicts.
async fn run_worker_job(
    job: &serde_json::Value,
    objective: &str,
    provider_for: Option<&ProviderFor>,
) -> anyhow::Result<serde_json::Value> {
    let Some(pf) = provider_for else {
        anyhow::bail!("no provider configured on this worker");
    };
    let Some(provider) = pf("solver") else {
        anyhow::bail!("no provider for role 'solver'");
    };
    let allow = Allowlist::new(
        &job["allow"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["127.0.0.1".into(), "localhost".into()]),
    );
    let (findings_tx, mut findings_rx) = mpsc::channel(64);
    let spend = Arc::new(Mutex::new(Spend::default()));
    let backend: Arc<dyn SandboxBackend> = Arc::new(HostBackend);
    let handle = backend
        .provision(&SandboxSpec {
            backend: BackendKind::Docker,
            image: "host".into(),
            cpus: 1,
            mem_mb: 512,
            mounts: vec![],
            egress_allow: vec![],
        })
        .await?;
    let mut registry = ToolRegistry::default();
    registry.register(Arc::new(TerminalTool { backend: backend.clone(), handle: handle.clone() }));
    registry.register(Arc::new(HttpTool {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        allow: allow.clone(),
        limiter: None,
        session: Arc::new(Mutex::new(impls::SessionStore::default())),
    }));
    registry.register(Arc::new(ScopeCheckTool { allow: allow.clone() }));
    registry.register(Arc::new(ValidatorSubmitTool { tx: findings_tx }));
    let turns = job["turns"].as_u64().unwrap_or(12) as u32;
    let outcome = aegis_core::run_agent(
        provider,
        &registry,
        "solver",
        format!("You are a melissacyber worker solver. {}", objective),
        objective.to_string(),
        turns,
        spend,
        None,
        None,
    )
    .await?;
    drop(registry);
    // Validate whatever the solver submitted.
    let _oob = OobStore::default();
    let mut validators = ValidatorRegistry::default();
    let probe = ProbeClient::new(None)?.with_allow(allow);
    validators.register(Arc::new(SqliValidator { probe: probe.clone() }));
    validators.register(Arc::new(XssValidator { probe: probe.clone() }));
    validators.register(Arc::new(CmdInjectionValidator { probe: probe.clone() }));
    validators.register(Arc::new(SstiValidator { probe: probe.clone() }));
    validators.register(Arc::new(FilePathValidator { probe: probe.clone() }));
    validators.register(Arc::new(ReplayValidator { probe }));
    let mut verdicts = vec![];
    while let Ok(f) = findings_rx.try_recv() {
        if let Some(v) = validators.get(&f.class) {
            let verdict = v.validate(&f).await;
            verdicts.push(json!({
                "title": f.title, "class": format!("{:?}", f.class),
                "verdict": format!("{:?}", verdict),
            }));
        }
    }
    Ok(json!({
        "status": "done",
        "turns": outcome.turns,
        "finished": outcome.finished_reason,
        "verdicts": verdicts,
    }))
}

/// `aegis arena` — self-play: attacker policy vs defender policy over N
/// rounds against a seeded vulnerable target, judged deterministically,
/// exporting JSONL traces for future aegis-sec SFT.
pub async fn arena(rounds: usize) -> anyhow::Result<()> {
    use aegis_core::{apply, append_trace, judge, ArenaScore, ArenaTrace};
    // Attacker policy: a real provider when configured, else the seeded set.
    let attacker = env_provider_for().ok().and_then(|pf| pf("solver"));
    let seeded = [
        "GET /search?q=' OR '1'='1",
        "GET /tpl?s={{691*689}}",
        "GET /read?f=../../../../etc/passwd",
        "GET /exec?c=;echo AEGIS",
    ];
    let mut score = ArenaScore { attacker: 0, defender: 0 };
    let trace_path = std::path::Path::new("arena_traces.jsonl");
    let _ = std::fs::remove_file(trace_path);
    let mut defender_rules: Vec<String> = vec![];
    for r in 0..rounds {
        let attack = if let Some(p) = &attacker {
            let msgs = vec![
                aegis_gateway::Message::system(
                    "You are an attacker policy in a self-play arena. Propose ONE raw HTTP attack request line targeting a vulnerable web lab, in the form 'GET /path?param=payload'. Avoid previously used payloads. Reply with ONLY the request line.",
                ),
                aegis_gateway::Message::user(format!(
                    "Round {r}. Defender rules so far: {}",
                    defender_rules.join(" | ")
                )),
            ];
            match p.complete(&msgs, &[]).await {
                Ok(c) => {
                    let line = c.message.content.lines().next().unwrap_or("").trim().to_string();
                    if line.starts_with("GET ") || line.starts_with("POST ") {
                        line
                    } else {
                        seeded[(r as usize) % seeded.len()].to_string()
                    }
                }
                Err(_) => seeded[(r as usize) % seeded.len()].to_string(),
            }
        } else {
            seeded[(r as usize) % seeded.len()].to_string()
        };
        let attack = attack.as_str();
        // Deterministic stand-in for the target: attacker "lands" when the
        // payload class is one the seeded app is vulnerable to.
        let response = if attack.contains("691*689") { "475906" } else { "" };
        let (landed, detected) = judge(attack, &defender_rules, response);
        apply(&mut score, landed, detected);
        append_trace(trace_path, &ArenaTrace {
            round: r as u32,
            attack_request: attack.to_string(),
            defender_rules: defender_rules.clone(),
            landed,
            detected,
        })?;
        // Defender learns: after an undetected hit it gains a rule.
        if landed && !detected {
            let sig = attack.split('?').nth(1).unwrap_or("").split('=').next().unwrap_or("");
            defender_rules.push(format!("title: learned-{r}
cs-uri-query|contains: '{sig}'"));
        }
    }
    println!("arena done: attacker {} - defender {} (traces: arena_traces.jsonl)",
        score.attacker, score.defender);
    Ok(())
}

/// `aegis pack list` — enumerate installed domain packs from ./packs.
pub fn pack_list() {
    let mut found = vec![];
    if let Ok(rd) = std::fs::read_dir("packs") {
        for e in rd.flatten() {
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&t) {
                    found.push(format!(
                        "{} v{} ({} agents)",
                        v["name"].as_str().unwrap_or("?"),
                        v["version"].as_str().unwrap_or("?"),
                        v["agents"].as_sequence().map(|a| a.len()).unwrap_or(0)
                    ));
                }
            }
        }
    }
    if found.is_empty() { println!("no packs installed (see ./packs)"); }
    for f in found { println!("pack: {f}"); }
}


fn which_chrome() -> anyhow::Result<String> {
    for c in ["google-chrome", "chromium", "chromium-browser", "chrome"] {
        if std::process::Command::new("sh")
            .args(["-c", &format!("command -v {c}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Ok(c.to_string());
        }
    }
    anyhow::bail!("no chrome binary found")
}

/// Install a pack from a git URL or a local directory into packs/.
pub fn pack_install(source: &str) {
    let packs = std::path::Path::new("packs");
    std::fs::create_dir_all(packs).ok();
    let name = std::path::Path::new(source.trim_end_matches('/'))
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("pack")
        .to_string();
    let dest = packs.join(&name);
    if source.starts_with("http") || source.starts_with("git@") {
        let st = std::process::Command::new("git")
            .args(["clone", "--depth", "1", source])
            .arg(&dest)
            .status();
        match st {
            Ok(s) if s.success() => println!("installed pack '{name}' from {source}"),
            _ => eprintln!("pack install failed for {source}"),
        }
    } else {
        let src = std::path::Path::new(source);
        if src.is_dir() {
            std::process::Command::new("cp")
                .args(["-r", source])
                .arg(&dest)
                .status()
                .ok();
            println!("installed pack '{name}' from {source}");
        } else {
            eprintln!("pack install: not a dir or url: {source}");
        }
    }
}

/// Scaffold a new pack yaml.
pub fn pack_new(name: &str) {
    let packs = std::path::Path::new("packs");
    std::fs::create_dir_all(packs).ok();
    let f = packs.join(format!("{name}.yaml"));
    std::fs::write(
        &f,
        format!("name: {name}\nversion: 0.1.0\nagents: []\nvalidators: []\n"),
    )
    .ok();
    println!("scaffolded {}", f.display());
}

pub fn pack_remove(name: &str) {
    let f = std::path::Path::new("packs").join(format!("{name}.yaml"));
    let d = std::path::Path::new("packs").join(name);
    let mut removed = false;
    if f.exists() {
        removed |= std::fs::remove_file(&f).is_ok();
    }
    if d.is_dir() {
        removed |= std::fs::remove_dir_all(&d).is_ok();
    }
    println!("{}", if removed { format!("removed pack '{name}'") } else { format!("pack '{name}' not found") });
}


fn load_resume_keys(dir: &std::path::Path) -> std::collections::HashSet<(String, String, String)> {
    std::fs::read_to_string(dir.join("verified_keys.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Rough CVSS 3.1 base-score estimate per class+severity — heuristic, not
/// a real vector evaluation; labelled as an estimate in the report.
fn cvss_estimate(class: &aegis_validate::FindingClass, severity: aegis_validate::Severity) -> f64 {
    use aegis_validate::{FindingClass as C, Severity as S};
    let base: f64 = match class {
        C::CmdInjection => 9.8,
        C::Sqli => 9.1,
        C::Ssrf => 8.6,
        C::Xxe => 8.2,
        C::Authn | C::AuthzIdor => 8.8,
        C::Nosqli => 8.9,
        C::Smuggling => 7.9,
        C::Deserialization => 9.0,
        C::Race => 6.8,
        C::Crypto => 5.9,
        C::Crash => 7.3,
        C::OpenRedirect => 6.1,
        C::HostHeader => 6.4,
        C::Secrets => 7.4,
        C::Csrf => 6.5,
        C::FileUpload => 8.1,
        C::BusinessLogic => 6.5,
        C::Ssti => 9.0,
        C::FilePath => 7.5,
        C::Xss => 6.1,
        C::Cors => 6.5,
        C::SessionJwt => 8.1,
        C::InfoDisclosure => 5.3,
        C::Other => 5.0,
    };
    match severity {
        S::Critical => base,
        S::High => base * 0.9,
        S::Medium => base * 0.7,
        S::Low => base * 0.4,
        S::Info => base * 0.2,
    }
    .min(10.0f64)
}
