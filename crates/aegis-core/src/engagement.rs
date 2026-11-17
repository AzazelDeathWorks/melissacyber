//! Engagement orchestration: scope -> discovery -> solvers -> validators
//! -> verified findings -> report.

use crate::coordinator::{Coordinator, EndpointTask, Param, MVP_CLASSES};
use aegis_validate::FindingClass;
use crate::prompts;
use crate::runner::run_agent;
use aegis_gateway::LlmProvider;
use aegis_kg::KnowledgeGraph;
use aegis_knowledge::selfop::SelfOp;
use aegis_knowledge::PatternLibrary;
use aegis_scope::Scope;
use aegis_tools::{Spend, SpawnRequest, ToolRegistry};
use aegis_validate::{Finding, ValidatorRegistry, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

pub type EngagementId = Uuid;

/// Engagement mode — the red/blue/purple loop nobody else ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Red,
    Blue,
    Purple,
    Deep,
    /// Dual-mode (Astra/AWS): systematic swarm + one free-roam
    /// bounty-hunter agent running unscripted alongside it.
    Bounty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub id: EngagementId,
    pub mode: Mode,
    pub budget: crate::budget::Budget,
}

/// Everything an engagement run needs — built by the CLI.
pub struct EngagementCtx {
    pub scope: Scope,
    pub registry: Arc<ToolRegistry>,
    pub findings_rx: mpsc::Receiver<Finding>,
    pub spawn_rx: mpsc::Receiver<SpawnRequest>,
    pub validators: Arc<ValidatorRegistry>,
    pub kg: Arc<Mutex<KnowledgeGraph>>,
    pub spend: Arc<Mutex<Spend>>,
    pub budget: crate::budget::Budget,
    pub solver_turns: u32,
    pub discovery_turns: u32,
    pub artifacts_dir: PathBuf,
    /// Sampling-and-verify: N solver variants per objective (Big Sleep
    /// pattern — different strategies, validator picks the winner).
    pub samples: usize,
    /// Experience flywheel — verified findings feed future runs.
    pub patterns: Arc<Mutex<PatternLibrary>>,
    /// Role -> (usd per 1M input, per 1M output) for spend tracking.
    pub prices: std::collections::HashMap<String, (f64, f64)>,
    /// Solver transcripts land here (audit + SFT data).
    pub traces_dir: PathBuf,
    /// Param-less sweeps per endpoint (info disclosure, cors).
    pub sweeps: bool,
    /// Skip the discovery wave (resume: KG restored from journal).
    pub skip_discovery: bool,
    /// Dedup keys from a previous partial run (resume).
    pub resume_keys: Arc<Mutex<HashSet<(String, String, String)>>>,
    /// packs/ dir for domain-pack hints injected into objectives.
    pub packs_dir: std::path::PathBuf,
    /// Policy broker — every tool call is gated/audited when set.
    pub policy: Option<std::sync::Arc<aegis_tools::broker::PolicyBroker>>,
    /// Bounty-hunter mode: one free agent alongside the swarm.
    pub bounty_sidecar: bool,
    /// SelfOp bandit — solver prompt variants, rewarded by verified findings.
    pub selfop: Arc<Mutex<aegis_knowledge::selfop::SelfOp>>,
    /// Scope-checked probe for deterministic surface mining (path fuzz).
    pub probe: Option<aegis_validate::ProbeClient>,
}

#[derive(Debug)]
pub struct EngagementResult {
    pub verified: Vec<(Finding, Verdict)>,
    /// Findings the validators/critic turned away, with reasons — the
    /// report's "attempted but unproven" section comes from this.
    pub rejected_list: Vec<(String, String)>,
    pub rejected: usize,
    pub endpoints: usize,
    pub solver_runs: usize,
    /// Solver tasks that errored (never silently dropped).
    pub solver_errors: usize,
    /// Per-stage funnel telemetry (RunSybil): where the pipeline gains
    /// and loses findings.
    pub funnel: FunnelStats,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FunnelStats {
    pub endpoints: usize,
    pub solver_runs: usize,
    pub candidates: usize,
    pub critic_killed: usize,
    pub prefilter_killed: usize,
    pub verified: usize,
    pub rejected: usize,
    pub informational: usize,
    pub solver_errors: usize,
}

/// A function that resolves a role to a provider (primary; fallbacks are
/// a router concern upstream). Injected so tests can hand in mocks.
pub type ProviderFor = Arc<dyn Fn(&str) -> Option<Arc<dyn LlmProvider>> + Send + Sync>;

/// Common parameter names guessed on endpoints where discovery found no
/// injectable parameter, with the vuln classes each name plausibly maps
/// to — keeps coverage bounded instead of the full class matrix.
const PARAM_GUESSES: &[(&str, &[FindingClass])] = &[
    ("q", &[FindingClass::Sqli, FindingClass::Xss, FindingClass::Ssti]),
    ("search", &[FindingClass::Xss, FindingClass::Sqli]),
    ("id", &[FindingClass::Sqli, FindingClass::AuthzIdor]),
    ("u", &[FindingClass::Sqli]),
    ("p", &[FindingClass::Sqli]),
    ("cmd", &[FindingClass::CmdInjection]),
    ("exec", &[FindingClass::CmdInjection]),
    ("host", &[FindingClass::Ssrf, FindingClass::CmdInjection]),
    ("url", &[FindingClass::Ssrf]),
    ("target", &[FindingClass::Ssrf]),
    ("path", &[FindingClass::FilePath, FindingClass::Ssrf]),
    ("file", &[FindingClass::FilePath]),
    ("expr", &[FindingClass::Ssti, FindingClass::CmdInjection]),
    ("redirect", &[FindingClass::OpenRedirect]),
    ("callback", &[FindingClass::Ssrf]),
];

pub async fn run_engagement(
    ctx: &mut EngagementCtx,
    provider_for: ProviderFor,
) -> anyhow::Result<EngagementResult> {
    let sem = Arc::new(Semaphore::new(ctx.budget.max_parallel));
    let _ = std::fs::create_dir_all(&ctx.traces_dir);
    // Journal: append-only engagement event log (resume + forensics).
    let journal = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(ctx.traces_dir.join("journal.jsonl"))
            .ok(),
    ));
    let jlog = |journal: &Mutex<Option<std::fs::File>>, ev: serde_json::Value| {
        if let Some(f) = journal.lock().unwrap().as_mut() {
            use std::io::Write;
            let _ = writeln!(f, "{}", ev);
        }
    };

    // Take the receivers out of ctx so spawned tasks can own them.
    let (sink_tx, sink_rx) = mpsc::channel::<Finding>(1);
    let mut findings_rx = std::mem::replace(&mut ctx.findings_rx, sink_rx);
    drop(sink_tx);
    let (sink2_tx, sink2_rx) = mpsc::channel::<SpawnRequest>(1);
    let mut spawn_rx = std::mem::replace(&mut ctx.spawn_rx, sink2_rx);
    drop(sink2_tx);

    // --- Wave 1: discovery ---
    if !ctx.skip_discovery {
        info!("engagement: discovery wave");
    if let Some(p) = provider_for("discovery") {
        let outcome = run_agent(
            p,
            &ctx.registry,
            "discovery",
            prompts::discovery_system(&ctx.scope),
            "Map the target's attack surface. Enumerate endpoints and \
             parameters; record every endpoint in the KG (kg_write, \
             kind=endpoint, data={url, params:[{name,in}]} — 'in' is \
             query|form|body|json|header|path."
                .into(),
            ctx.discovery_turns,
            ctx.spend.clone(),
            ctx.prices.get("discovery").copied(),
            ctx.policy.as_deref(),
        )
        .await?;
        info!(turns = outcome.turns, reason = %outcome.finished_reason, "discovery done");
        jlog(&journal, serde_json::json!({"event":"discovery","turns":outcome.turns,"reason":outcome.finished_reason}));
        let tid = Uuid::new_v4();
        let _ = std::fs::write(
            ctx.traces_dir.join(format!("discovery-{tid}.jsonl")),
            outcome
                .transcript
                .iter()
                .map(|m| serde_json::to_string(m).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    } // !skip_discovery

    let mut tasks = Coordinator::endpoint_tasks(&ctx.kg.lock().unwrap());
    info!(endpoints = tasks.len(), "discovery produced endpoints");

    // Deterministic surface mining: LLM discovery only sees what pages
    // link to — unlinked sinks (admin panels, debug endpoints, stray API
    // routes) need a path wordlist. A random-path request per target sets
    // the "not found" baseline; anything deviating is a real endpoint.
    if let Some(probe) = &ctx.probe {
        const COMMON_PATHS: &[&str] = &[
            "/admin", "/login", "/api", "/api/v1", "/api/health", "/api/calc",
            "/api/exec", "/api/run", "/api/status", "/api/users", "/backup",
            "/backup/config.json", "/robots.txt", "/sitemap.xml", "/health",
            "/status", "/internal-status", "/server-status", "/metrics",
            "/config", "/.env", "/flag", "/ping", "/upload", "/debug", "/test",
            "/console", "/docs", "/swagger.json", "/openapi.json",
            "/actuator", "/actuator/health", "/graphql",
        ];
        let mut known: HashSet<String> = tasks.iter().map(|t| t.url.clone()).collect();
        for t in &ctx.scope.targets {
            let base = t.value.trim_end_matches('/');
            let probe_url = format!("{base}/aegis-mine-{:x}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos());
            let baseline = probe.get(&probe_url, &Default::default()).await.ok();
            for path in COMMON_PATHS {
                let url = format!("{base}{path}");
                if known.contains(&url) {
                    continue;
                }
                if let Ok(r) = probe.get(&url, &Default::default()).await {
                    let differs = match &baseline {
                        Some(b) => {
                            r.status != b.status
                                || (r.body.len() as i64 - b.body.len() as i64).abs() > 32
                        }
                        None => r.status != 404,
                    };
                    if differs {
                        info!(url = %url, status = r.status, "surface mining hit");
                        known.insert(url.clone());
                        tasks.push(EndpointTask { url, params: vec![] });
                    }
                }
            }
        }
        info!(endpoints = tasks.len(), "surface mining complete");
    }

    // Discovery failure resilience: zero endpoints must not mean zero
    // coverage — synthesize tasks from the scope base targets with common
    // parameter guesses so solvers still mine the surface.
    if tasks.is_empty() {
        for t in &ctx.scope.targets {
            tasks.push(EndpointTask {
                url: t.value.clone(),
                params: PARAM_GUESSES
                    .iter()
                    .map(|(n, _)| Param { name: n.to_string(), r#in: "query".into() })
                    .collect(),
            });
        }
        warn!(synthesized = tasks.len(), "discovery empty — synthesized fallback tasks");
    }

    // --- Wave 2: solver swarm (bounded parallel, fresh context each) ---
    //
    // Order jobs by pattern-library prior (PAG-lite: expected value of
    // each class on this engagement's history) — highest-yield first.
    let strategies = [
        "direct payloads first",
        "encoding / filter-bypass variants",
        "alternative vector: time-based or out-of-band",
    ];
    let mut jobs: Vec<(EndpointTask, Param, FindingClass)> = vec![];
    for task in &tasks {
        if task.params.is_empty() {
            // Discovery found the endpoint but no injectable param —
            // guess common names with per-class affinity instead of the
            // full class matrix.
            for (pname, classes) in PARAM_GUESSES {
                for class in *classes {
                    jobs.push((
                        task.clone(),
                        Param { name: pname.to_string(), r#in: "query".into() },
                        *class,
                    ));
                }
            }
        } else {
            for param in &task.params {
                for class in MVP_CLASSES {
                    jobs.push((task.clone(), param.clone(), *class));
                }
            }
        }
    }
    {
        let lib = ctx.patterns.lock().unwrap();
        jobs.sort_by_key(|(_, _, c)| std::cmp::Reverse(lib.class_prior(&format!("{c:?}").to_lowercase())));
    }

    let target_host = ctx
        .scope
        .targets
        .iter()
        .find_map(|t| reqwest::Url::parse(&t.value).ok().and_then(|u| u.host_str().map(String::from)))
        .unwrap_or_default();
    let few_shot = ctx.patterns.lock().unwrap().few_shot_for(&target_host, 5);
    // objective key -> selfop variant id, so verdicts can reward the
    // prompt variant that produced them.
    let variant_map = Arc::new(Mutex::new(std::collections::HashMap::<String, String>::new()));
    let mut handles = vec![];
    let mut solver_runs = 0usize;
    // Param-less sweeps: info disclosure + CORS on every endpoint.
    let mut sweep_jobs: Vec<(String, FindingClass)> = vec![];
    if ctx.sweeps {
        for task in &tasks {
            for class in Coordinator::SWEEP_CLASSES {
                sweep_jobs.push((task.url.clone(), *class));
            }
        }
    }

    // LATS-lite route search: routes are (endpoint,param,class,strategy);
    // each round spawns the UCB-best unmasked routes, then learns from the
    // verified set — failed routes get masked, verified routes expand via
    // milestone follow-ups later.
    let mut search = crate::search::RouteSearch::default();
    for (task, param, class) in &jobs {
        for sample in 0..ctx.samples.max(1) {
            search.add_route(crate::search::Route {
                url: task.url.clone(),
                param: param.name.clone(),
                class: format!("{class:?}").to_lowercase(),
                strategy: sample,
            });
        }
    }

    'outer: for (task, param, class) in &jobs {
        for sample in 0..ctx.samples.max(1) {
            if solver_runs >= ctx.budget.max_agents || ctx.budget.exhausted() {
                warn!("budget/agent cap reached — frontier truncated");
                break 'outer;
            }
            // Action masking: never re-walk a masked route.
            let route_key = crate::search::Route {
                url: task.url.clone(),
                param: param.name.clone(),
                class: format!("{class:?}").to_lowercase(),
                strategy: sample,
            };
            if search.nodes.get(&route_key).is_some_and(|n| n.masked) {
                continue;
            }
            let Some(provider) = provider_for("solver") else {
                anyhow::bail!("no provider for role 'solver'");
            };
            solver_runs += 1;
            let mut objective = Coordinator::solver_objective(task, param, class)
                + &Coordinator::pack_hint(&ctx.packs_dir, class);
            if ctx.samples > 1 {
                objective.push_str(&format!(
                    "\nSampling variant {}/{}: try {}.",
                    sample + 1,
                    ctx.samples,
                    strategies[sample % strategies.len()],
                ));
            }
            // Semantic recall (pgvector-equivalent): retrieve patterns
            // similar to THIS objective, not just the top host patterns.
            let recalled = ctx
                .patterns
                .lock()
                .unwrap()
                .semantic_hints(&target_host, &format!("{} {} {:?}", task.url, param.name, class), 3);
            let hint_block = if !recalled.is_empty() { recalled } else { few_shot.clone() };
            if !hint_block.is_empty() {
                objective.push_str(&format!("\nVerified patterns from past engagements:\n{hint_block}"));
            }
            let variant = ctx.selfop.lock().unwrap().pick().map(|v| (v.id.clone(), v.hint.clone()));
            let mut sys_extra = String::new();
            if let Some((vid, hint)) = variant {
                variant_map
                    .lock()
                    .unwrap()
                    .insert(format!("{}|{}|{:?}", task.url, param.name, class), vid);
                if !hint.is_empty() {
                    sys_extra = format!("\n\nStrategy hint (self-evolved): {hint}");
                }
            }
            let reg = ctx.registry.clone();
            let sys = prompts::solver_system(&ctx.scope) + &sys_extra;
            let spend = ctx.spend.clone();
            let turns = ctx.solver_turns;
            let permit = sem.clone();
            let price = ctx.prices.get("solver").copied();
            let tdir = ctx.traces_dir.clone();
            let policy = ctx.policy.clone();
            let route_for_task = route_key.clone();
            handles.push(tokio::spawn(async move {
                let _p = permit.acquire().await.unwrap();
                let r = run_agent(provider, &reg, "solver", sys, objective, turns, spend, price, policy.as_deref()).await;
                if let Ok(o) = &r {
                    let tid = Uuid::new_v4();
                    let _ = std::fs::write(
                        tdir.join(format!("solver-{tid}.jsonl")),
                        o.transcript
                            .iter()
                            .map(|m| serde_json::to_string(m).unwrap_or_default())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
                (r, route_for_task)
            }));
        }
    }
    let mut sweep_handles = vec![];
    for (url, class) in &sweep_jobs {
        if solver_runs >= ctx.budget.max_agents || ctx.budget.exhausted() {
            break;
        }
        let Some(provider) = provider_for("solver") else {
            anyhow::bail!("no provider for role 'solver'");
        };
        solver_runs += 1;
        let objective = Coordinator::sweep_objective(url, class)
            + &Coordinator::pack_hint(&ctx.packs_dir, class);
        let reg = ctx.registry.clone();
        let sys = prompts::solver_system(&ctx.scope);
        let spend = ctx.spend.clone();
        let turns = ctx.solver_turns;
        let permit = sem.clone();
        let price = ctx.prices.get("solver").copied();
        let tdir = ctx.traces_dir.clone();
        let policy = ctx.policy.clone();
        sweep_handles.push(tokio::spawn(async move {
            let _p = permit.acquire().await.unwrap();
            let r = run_agent(provider, &reg, "solver", sys, objective, turns, spend, price, policy.as_deref()).await;
            if let Ok(o) = &r {
                let tid = Uuid::new_v4();
                let _ = std::fs::write(
                    tdir.join(format!("solver-{tid}.jsonl")),
                    o.transcript
                        .iter()
                        .map(|m| serde_json::to_string(m).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
            r
        }));
    }
    info!(solver_runs, sweeps = sweep_jobs.len(), samples = ctx.samples, "solver wave spawned");

    // Bounty-hunter sidecar (dual-mode): one unscripted free agent that
    // hunts like a human researcher — intuition, chaining, no checklist.
    if ctx.bounty_sidecar {
        if let Some(provider) = provider_for("solver") {
            solver_runs += 1;
            let reg = ctx.registry.clone();
            let sys = prompts::solver_system(&ctx.scope);
            let spend = ctx.spend.clone();
            let policy = ctx.policy.clone();
            let tdir = ctx.traces_dir.clone();
            let targets = ctx.scope.targets.iter().map(|t| t.value.clone()).collect::<Vec<_>>().join(", ");
            handles.push(tokio::spawn(async move {
                let r = run_agent(
                    provider, &reg, "solver", sys,
                    format!(
                        "You are a bug bounty hunter on {targets}. No checklist — hunt freely: reconnaissance, auth analysis, logic flaws, chaining. Submit anything concrete via validator_submit."
                    ),
                    40, spend, None, policy.as_deref(),
                ).await;
                if let Ok(o) = &r {
                    let _ = std::fs::write(
                        tdir.join(format!("bounty-{}.jsonl", Uuid::new_v4())),
                        o.transcript.iter().map(|m| serde_json::to_string(m).unwrap_or_default()).collect::<Vec<_>>().join("\n"),
                    );
                }
                (r, crate::search::Route { url: String::new(), param: String::new(), class: "bounty".into(), strategy: 0 })
            }));
        }
    }

    // --- Validator intake (runs until shutdown signal) ---
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (tx_verified, mut rx_verified) = mpsc::channel::<(Finding, Verdict)>(256);
    let validators = ctx.validators.clone();
    let critic = provider_for("critic");
    let patterns = ctx.patterns.clone();
    let rejected = Arc::new(Mutex::new(0usize));
    let rejected_list = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let variant_map_intake = variant_map.clone();
    let selfop_intake = ctx.selfop.clone();
    let rej = rejected.clone();
    let rejl = rejected_list.clone();
    let cand = Arc::new(Mutex::new(0usize));
    let pfk = Arc::new(Mutex::new(0usize));
    let ck = Arc::new(Mutex::new(0usize));
    let inf = Arc::new(Mutex::new(0usize));
    let cand_out = cand.clone();
    let pfk_out = pfk.clone();
    let ck_out = ck.clone();
    let inf_out = inf.clone();
    let intake = tokio::spawn(async move {
        async fn handle(
            f: Finding,
            validators: Arc<ValidatorRegistry>,
            rej: Arc<Mutex<usize>>,
            rejl: Arc<Mutex<Vec<(String, String)>>>,
            tx: mpsc::Sender<(Finding, Verdict)>,
            critic: Option<Arc<dyn LlmProvider>>,
            patterns: Arc<Mutex<PatternLibrary>>,
            variant_map: Arc<Mutex<std::collections::HashMap<String, String>>>,
            selfop: Arc<Mutex<SelfOp>>,
            cand: Arc<Mutex<usize>>,
            pfk: Arc<Mutex<usize>>,
            ck: Arc<Mutex<usize>>,
            inf: Arc<Mutex<usize>>,
        ) {
            *cand.lock().unwrap() += 1;
            // Reachability prefilter (taint-lite): a candidate with no
            // request path can never be reproduced — kill before burning
            // critic+validator budget on it.
            let has_sink = !f.evidence["url"].as_str().unwrap_or("").is_empty()
                || !f.evidence["request"]["url"].as_str().unwrap_or("").is_empty();
            if !has_sink {
                *rej.lock().unwrap() += 1;
                *pfk.lock().unwrap() += 1;
                rejl.lock().unwrap()
                    .push((f.title.clone(), "unreachable: evidence has no request url".into()));
                return;
            }
            // Critic gate (LLM, advisory): slop filter before determinism.
            if let Some(c) = &critic {
                use aegis_gateway::Message;
                let verdict_txt = c
                    .complete(
                        &[
                            Message::system(
                                "You are a security-review critic. Given a candidate finding's JSON,                                  answer with exactly 'pass' if it is a plausible, evidence-backed                                  vulnerability claim, or 'reject' if it is slop/hallucination                                  (no concrete evidence, impossible class, or missing context).",
                            ),
                            Message::user(serde_json::to_string(&f).unwrap_or_default()),
                        ],
                        &[],
                    )
                    .await
                    .map(|r| r.message.content.to_lowercase())
                    .unwrap_or_else(|_| "pass".into());
                if verdict_txt.contains("reject") && !verdict_txt.contains("pass") {
                    info!(title = %f.title, "finding killed by critic");
                    *rej.lock().unwrap() += 1;
                    *ck.lock().unwrap() += 1;
                    rejl.lock().unwrap()
                        .push((f.title.clone(), "killed by critic".into()));
                    return;
                }
            }
            match validators.get(&f.class) {
                Some(v) => {
                    let mut verdict = v.validate(&f).await;
                    // One bounded in-place retry for transient verdicts.
                    if matches!(verdict, Verdict::NeedsRetry { .. }) {
                        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                        verdict = v.validate(&f).await;
                    }
                    match &verdict {
                        Verdict::NeedsRetry { reason } => {
                            *rej.lock().unwrap() += 1;
                            rejl.lock().unwrap()
                                .push((f.title.clone(), format!("unstable: {reason}")));
                        }
                        Verdict::Informational { note } => {
                            *inf.lock().unwrap() += 1;
                            rejl.lock().unwrap()
                                .push((f.title.clone(), format!("informational: {note}")));
                        }
                        Verdict::Verified { reproduction } => {
                            // Second-verifier pass for high/critical: one
                            // independent re-validate before it enters the report.
                            if matches!(f.severity, aegis_validate::Severity::High | aegis_validate::Severity::Critical) {
                                let again = v.validate(&f).await;
                                if !matches!(again, Verdict::Verified { .. }) {
                                    info!(title=%f.title,"second verifier disagreed — rejected");
                                    *rej.lock().unwrap() += 1;
                                    rejl.lock().unwrap().push((
                                        f.title.clone(),
                                        "failed second-verifier pass".into(),
                                    ));
                                    return;
                                }
                            }
                            info!(title=%f.title,"finding VERIFIED");
                            let url = f.evidence["url"]
                                .as_str()
                                .or_else(|| f.evidence["request"]["url"].as_str())
                                .unwrap_or("");
                            let parsed = reqwest::Url::parse(url.split('?').next().unwrap_or(url)).ok();
                            let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("").to_string();
                            let path = parsed.as_ref().map(|u| u.path().to_string()).unwrap_or_else(|| url.to_string());
                            let param = f.evidence["param"].as_str().unwrap_or("");
                            patterns.lock().unwrap().record(
                                &format!("{:?}", f.class).to_lowercase(),
                                &format!("{}{}?{}=", host, path, param),
                                reproduction,
                            );
                            if let Some(vid) = variant_map.lock().unwrap()
                                .get(&format!("{}|{}|{:?}", f.evidence["url"].as_str().unwrap_or(""), param, f.class))
                                .cloned()
                            {
                                selfop.lock().unwrap().record(&vid, true);
                            }
                        }
                        Verdict::Rejected { reason } => {
                            if let Some(vid) = variant_map.lock().unwrap()
                                .get(&format!("{}|{}|{:?}", f.evidence["url"].as_str().unwrap_or(""), f.evidence["param"].as_str().unwrap_or(""), f.class))
                                .cloned()
                            {
                                selfop.lock().unwrap().record(&vid, false);
                            }
                            info!(title=%f.title,%reason,"finding rejected");
                            *rej.lock().unwrap() += 1;
                            rejl.lock().unwrap()
                                .push((f.title.clone(), reason.clone()));
                        }
                        Verdict::Preview { .. } => {}
                    }
                    let _ = tx.send((f, verdict)).await;
                }
                None => {
                    *rej.lock().unwrap() += 1;
                    rejl.lock().unwrap()
                        .push((f.title.clone(), format!("no validator for {:?}", f.class)));
                    warn!(class=?f.class,"no validator for class — dropped");
                }
            }
        }

        // Bounded-parallel intake: SSRF's 5s OOB wait must not stall the
        // queue — validate up to 8 findings concurrently.
        let mut set: JoinSet<()> = JoinSet::new();
        let spawn_h = |f: Finding,
                           set: &mut JoinSet<()>,
                           validators: &Arc<ValidatorRegistry>,
                           rej: &Arc<Mutex<usize>>,
                           rejl: &Arc<Mutex<Vec<(String, String)>>>,
                           tx: &mpsc::Sender<(Finding, Verdict)>,
                           critic: &Option<Arc<dyn LlmProvider>>,
                           patterns: &Arc<Mutex<PatternLibrary>>,
                           vmap: &Arc<Mutex<std::collections::HashMap<String, String>>>,
                           sop: &Arc<Mutex<SelfOp>>,
                           cand: &Arc<Mutex<usize>>,
                           pfk: &Arc<Mutex<usize>>,
                           ck: &Arc<Mutex<usize>>,
                           inf: &Arc<Mutex<usize>>| {
            while set.len() >= 8 {
                // can't await inside closure — caller drains
                break;
            }
            set.spawn(handle(
                f,
                validators.clone(),
                rej.clone(),
                rejl.clone(),
                tx.clone(),
                critic.clone(),
                patterns.clone(),
                vmap.clone(),
                sop.clone(),
                cand.clone(),
                pfk.clone(),
                ck.clone(),
                inf.clone(),
            ));
        };
        let mut stopping = false;
        loop {
            if set.len() >= 8 {
                let _ = set.join_next().await;
                continue;
            }
            if stopping {
                match findings_rx.try_recv() {
                    Ok(f) => {
                        spawn_h(f, &mut set, &validators, &rej, &rejl, &tx_verified, &critic, &patterns, &variant_map_intake, &selfop_intake, &cand, &pfk, &ck, &inf)
                    }
                    Err(_) => break,
                }
                continue;
            }
            tokio::select! {
                _ = &mut stop_rx => stopping = true,
                maybe = findings_rx.recv() => {
                    match maybe {
                        Some(f) => spawn_h(f, &mut set, &validators, &rej, &rejl, &tx_verified, &critic, &patterns, &variant_map_intake, &selfop_intake, &cand, &pfk, &ck, &inf),
                        None => break,
                    }
                }
            }
        }
        while set.join_next().await.is_some() {}
    });

    let verified_so_far = Arc::new(Mutex::new(Vec::<(Finding, Verdict)>::new()));
    let vsf = verified_so_far.clone();
    let ctx_resume_keys = ctx.resume_keys.clone();
    let collect = tokio::spawn(async move {
        let mut verified: Vec<(Finding, Verdict)> = vec![];
        let mut seen: HashSet<(String, String, String)> =
            ctx_resume_keys.lock().unwrap().clone();
        while let Some(fv) = rx_verified.recv().await {
            if matches!(fv.1, Verdict::Verified { .. }) {
                vsf.lock().unwrap().push((fv.0.clone(), fv.1.clone()));
                let url = fv.0.evidence["url"]
                    .as_str()
                    .or_else(|| fv.0.evidence["request"]["url"].as_str())
                    .unwrap_or("");
                let path = reqwest::Url::parse(url)
                    .map(|u| u.path().to_string())
                    .unwrap_or_else(|_| url.split('?').next().unwrap_or(url).to_string());
                let key = (
                    format!("{:?}", fv.0.class),
                    path,
                    fv.0.evidence["param"].as_str().unwrap_or("").to_string(),
                );
                if !seen.insert(key) {
                    info!(title = %fv.0.title, "duplicate verified finding — deduped");
                    continue;
                }
            }
            verified.push(fv);
        }
        ctx_resume_keys.lock().unwrap().extend(seen);
        verified
    });

    let mut solver_errors = 0usize;
    let mut spawned_routes: Vec<crate::search::Route> = vec![];
    for h in handles {
        match h.await {
            Ok((Ok(_), route)) => spawned_routes.push(route),
            Ok((Err(e), route)) => {
                solver_errors += 1;
                spawned_routes.push(route);
                warn!(err = %e, "solver failed");
            }
            Err(e) => {
                solver_errors += 1;
                warn!(err = %e, "solver task panicked/cancelled");
            }
        }
    }
    for h in sweep_handles {
        if let Err(e) = h.await {
            warn!(err = %e, "sweep task failed");
        }
    }

    // LATS learn pass: mark each spawned route verified/failed against
    // the validated set — masked routes were already skipped at spawn.
    {
        let verified_keys: std::collections::HashSet<(String, String)> = verified_so_far
            .lock()
            .unwrap()
            .iter()
            .map(|(f, _)| {
                let u = f.evidence["url"].as_str().unwrap_or("").split('?').next().unwrap_or("").to_string();
                (format!("{:?}", f.class).to_lowercase(), u)
            })
            .collect();
        for r in &spawned_routes {
            let path = reqwest::Url::parse(&r.url)
                .map(|u| u.path().to_string())
                .unwrap_or_else(|_| r.url.clone());
            let hits = verified_keys.iter().any(|(c, u)| {
                *c == r.class && (u.ends_with(&path) || r.url.ends_with(u))
            });
            if hits {
                search.verify(r);
            } else {
                search.fail(r);
            }
        }
        search.tick();
    }

    // Deferred spawn requests (agents queuing sub-agents mid-run).
    let mut extra = 0usize;
    while let Ok(req) = spawn_rx.try_recv() {
        if extra >= 8 {
            break;
        }
        extra += 1;
        info!(kind = %req.kind, "processing deferred spawn request");
        if let Some(provider) = provider_for("solver") {
            let _ = run_agent(
                provider,
                &ctx.registry,
                "solver",
                prompts::solver_system(&ctx.scope),
                req.objective,
                ctx.solver_turns,
                ctx.spend.clone(),
                ctx.prices.get("solver").copied(),
                ctx.policy.as_deref(),
            )
            .await;
        }
    }
    solver_runs += extra;

    // --- Wave 3: escalation — verified findings spawn follow-on work ---
    // (re-planning: file read -> creds hunt, SSTI/cmdi -> RCE chain,
    // sqli -> creds -> auth). Bounded, one round.
    let mut follow_ups: Vec<String> = vec![];
    {
        // Peek at verified findings collected so far is impossible — the
        // collector owns them. Instead, derive escalation objectives from
        // the same findings channel snapshot via patterns: verified ones
        // already called patterns.record(). Simpler and correct: scan the
        // verified vec AFTER collect — but the intake is still running;
        // so we snapshot via a shared list instead.
    }
    // Intake is still live; new solver findings will be validated.
    let mut escalation_runs = 0usize;
    {
        // Milestone decomposition (DoGNAVY): each verified finding expands
        // into stage-labelled follow-ups — primitive -> capability -> impact.
        let verified_snapshot = verified_so_far.lock().unwrap().clone();
        for (f, _) in &verified_snapshot {
            let url = f.evidence["url"].as_str().unwrap_or("?");
            let param = f.evidence["param"].as_str().unwrap_or("");
            for (stage, obj) in crate::search::milestone_followups(
                &format!("{:?}", f.class).to_lowercase(), url, param,
            ) {
                follow_ups.push(format!(
                    "[milestone:{stage}] {obj} Submit via validator_submit."
                ));
            }
        }
    }
    for objective in follow_ups.iter().take(4) {
        if solver_runs >= ctx.budget.max_agents || ctx.budget.exhausted() {
            break;
        }
        let Some(provider) = provider_for("solver") else { break };
        let reg = ctx.registry.clone();
        let sys = prompts::solver_system(&ctx.scope);
        let spend = ctx.spend.clone();
        let price = ctx.prices.get("solver").copied();
        let tdir = ctx.traces_dir.clone();
        escalation_runs += 1;
        solver_runs += 1;
        if let Ok(o) = run_agent(provider, &reg, "solver", sys, objective.clone(), ctx.solver_turns, spend, price, ctx.policy.as_deref()).await {
            let _ = std::fs::write(
                tdir.join(format!("solver-escalation-{}.jsonl", Uuid::new_v4())),
                o.transcript.iter().map(|m| serde_json::to_string(m).unwrap_or_default()).collect::<Vec<_>>().join("\n"),
            );
        }
    }
    jlog(&journal, serde_json::json!({
        "event":"done","solver_runs":solver_runs,"errors":solver_errors,
        "escalations":escalation_runs,"rejected":*rejected.lock().unwrap()
    }));

    // Grace window for escalated findings to reach the validators.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let _ = stop_tx.send(());
    let _ = intake.await;
    let verified = collect.await.unwrap_or_default();
    let rejected = *rejected.lock().unwrap();
    let rejected_list_out: Vec<(String, String)> =
        rejected_list.lock().unwrap().iter().cloned().collect();

    let funnel = FunnelStats {
        endpoints: tasks.len(),
        solver_runs,
        candidates: *cand_out.lock().unwrap(),
        critic_killed: *ck_out.lock().unwrap(),
        prefilter_killed: *pfk_out.lock().unwrap(),
        verified: verified.len(),
        rejected,
        informational: *inf_out.lock().unwrap(),
        solver_errors,
    };
    Ok(EngagementResult {
        verified,
        rejected_list: rejected_list_out,
        rejected,
        endpoints: tasks.len(),
        solver_runs,
        solver_errors,
        funnel,
    })
}
