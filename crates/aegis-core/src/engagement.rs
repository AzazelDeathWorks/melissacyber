//! Engagement orchestration: scope -> discovery -> solvers -> validators
//! -> verified findings -> report.

use crate::coordinator::{Coordinator, EndpointTask, Param, MVP_CLASSES};
use aegis_validate::FindingClass;
use crate::prompts;
use crate::runner::run_agent;
use aegis_gateway::LlmProvider;
use aegis_kg::KnowledgeGraph;
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
}

/// A function that resolves a role to a provider (primary; fallbacks are
/// a router concern upstream). Injected so tests can hand in mocks.
pub type ProviderFor = Arc<dyn Fn(&str) -> Option<Arc<dyn LlmProvider>> + Send + Sync>;

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

    let tasks = Coordinator::endpoint_tasks(&ctx.kg.lock().unwrap());
    info!(endpoints = tasks.len(), "discovery produced endpoints");

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
        for param in &task.params {
            for class in MVP_CLASSES {
                jobs.push((task.clone(), param.clone(), *class));
            }
        }
    }
    {
        let lib = ctx.patterns.lock().unwrap();
        jobs.sort_by_key(|(_, _, c)| std::cmp::Reverse(lib.class_prior(&format!("{c:?}").to_lowercase())));
    }

    let few_shot = ctx.patterns.lock().unwrap().few_shot(5);
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

    'outer: for (task, param, class) in &jobs {
        for sample in 0..ctx.samples.max(1) {
            if solver_runs >= ctx.budget.max_agents || ctx.budget.exhausted() {
                warn!("budget/agent cap reached — frontier truncated");
                break 'outer;
            }
            let Some(provider) = provider_for("solver") else {
                anyhow::bail!("no provider for role 'solver'");
            };
            solver_runs += 1;
            let mut objective = Coordinator::solver_objective(task, param, class);
            if ctx.samples > 1 {
                objective.push_str(&format!(
                    "\nSampling variant {}/{}: try {}.",
                    sample + 1,
                    ctx.samples,
                    strategies[sample % strategies.len()],
                ));
            }
            if !few_shot.is_empty() {
                objective.push_str(&format!("\nVerified patterns from past engagements:\n{few_shot}"));
            }
            let reg = ctx.registry.clone();
            let sys = prompts::solver_system(&ctx.scope);
            let spend = ctx.spend.clone();
            let turns = ctx.solver_turns;
            let permit = sem.clone();
            let price = ctx.prices.get("solver").copied();
            let tdir = ctx.traces_dir.clone();
            handles.push(tokio::spawn(async move {
                let _p = permit.acquire().await.unwrap();
                let r = run_agent(provider, &reg, "solver", sys, objective, turns, spend, price).await;
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
    }
    for (url, class) in &sweep_jobs {
        if solver_runs >= ctx.budget.max_agents || ctx.budget.exhausted() {
            break;
        }
        let Some(provider) = provider_for("solver") else {
            anyhow::bail!("no provider for role 'solver'");
        };
        solver_runs += 1;
        let objective = Coordinator::sweep_objective(url, class);
        let reg = ctx.registry.clone();
        let sys = prompts::solver_system(&ctx.scope);
        let spend = ctx.spend.clone();
        let turns = ctx.solver_turns;
        let permit = sem.clone();
        let price = ctx.prices.get("solver").copied();
        let tdir = ctx.traces_dir.clone();
        handles.push(tokio::spawn(async move {
            let _p = permit.acquire().await.unwrap();
            let r = run_agent(provider, &reg, "solver", sys, objective, turns, spend, price).await;
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

    // --- Validator intake (runs until shutdown signal) ---
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (tx_verified, mut rx_verified) = mpsc::channel::<(Finding, Verdict)>(256);
    let validators = ctx.validators.clone();
    let critic = provider_for("critic");
    let patterns = ctx.patterns.clone();
    let rejected = Arc::new(Mutex::new(0usize));
    let rejected_list = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let rej = rejected.clone();
    let rejl = rejected_list.clone();
    let intake = tokio::spawn(async move {
        async fn handle(
            f: Finding,
            validators: Arc<ValidatorRegistry>,
            rej: Arc<Mutex<usize>>,
            rejl: Arc<Mutex<Vec<(String, String)>>>,
            tx: mpsc::Sender<(Finding, Verdict)>,
            critic: Option<Arc<dyn LlmProvider>>,
            patterns: Arc<Mutex<PatternLibrary>>,
        ) {
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
                    rejl.lock().unwrap()
                        .push((f.title.clone(), "killed by critic".into()));
                    return;
                }
            }
            match validators.get(&f.class) {
                Some(v) => {
                    let verdict = v.validate(&f).await;
                    match &verdict {
                        Verdict::Verified { reproduction } => {
                            info!(title=%f.title,"finding VERIFIED");
                            let url = f.evidence["url"].as_str().unwrap_or("");
                            let path = url.split('?').next().unwrap_or(url);
                            let hostless = reqwest::Url::parse(path)
                                .map(|u| u.path().to_string())
                                .unwrap_or_else(|_| path.to_string());
                            let param = f.evidence["param"].as_str().unwrap_or("");
                            patterns.lock().unwrap().record(
                                &format!("{:?}", f.class).to_lowercase(),
                                &format!("GET {}?{}=", hostless, param),
                                reproduction,
                            );
                        }
                        Verdict::Rejected { reason } => {
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
                           patterns: &Arc<Mutex<PatternLibrary>>| {
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
                        spawn_h(f, &mut set, &validators, &rej, &rejl, &tx_verified, &critic, &patterns)
                    }
                    Err(_) => break,
                }
                continue;
            }
            tokio::select! {
                _ = &mut stop_rx => stopping = true,
                maybe = findings_rx.recv() => {
                    match maybe {
                        Some(f) => spawn_h(f, &mut set, &validators, &rej, &rejl, &tx_verified, &critic, &patterns),
                        None => break,
                    }
                }
            }
        }
        while set.join_next().await.is_some() {}
    });

    let verified_so_far = Arc::new(Mutex::new(Vec::<(Finding, Verdict)>::new()));
    let vsf = verified_so_far.clone();
    let collect = tokio::spawn(async move {
        let mut verified: Vec<(Finding, Verdict)> = vec![];
        let mut seen: HashSet<(String, String, String)> = HashSet::new();
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
        verified
    });

    let mut solver_errors = 0usize;
    for h in handles {
        match h.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                solver_errors += 1;
                warn!(err = %e, "solver failed");
            }
            Err(e) => {
                solver_errors += 1;
                warn!(err = %e, "solver task panicked/cancelled");
            }
        }
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
        let verified_snapshot = verified_so_far.lock().unwrap().clone();
        for (f, _) in &verified_snapshot {
            let hint = match f.class {
                FindingClass::FilePath => "read app config/env files for credentials, then try them on login endpoints",
                FindingClass::Ssti | FindingClass::CmdInjection => "escalate to full RCE: enumerate the host, read secrets, attempt OOB exfil of a canary",
                FindingClass::Sqli => "extract schema/credentials and try them on discovered auth endpoints",
                _ => continue,
            };
            follow_ups.push(format!(
                "Prior verified finding: {:?} at {} — {}. Submit any new issue via validator_submit.",
                f.class,
                f.evidence["url"].as_str().unwrap_or("?"),
                hint
            ));
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
        if let Ok(o) = run_agent(provider, &reg, "solver", sys, objective.clone(), ctx.solver_turns, spend, price).await {
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

    Ok(EngagementResult {
        verified,
        rejected_list: rejected_list_out,
        rejected,
        endpoints: tasks.len(),
        solver_runs,
        solver_errors,
    })
}
