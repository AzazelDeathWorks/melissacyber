//! Engagement orchestration: scope -> discovery -> solvers -> validators
//! -> verified findings -> report.

use crate::coordinator::{Coordinator, EndpointTask, MVP_CLASSES};
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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, Semaphore};
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
}

#[derive(Debug)]
pub struct EngagementResult {
    pub verified: Vec<(Finding, Verdict)>,
    pub rejected: usize,
    pub endpoints: usize,
    pub solver_runs: usize,
}

/// A function that resolves a role to a provider (primary; fallbacks are
/// a router concern upstream). Injected so tests can hand in mocks.
pub type ProviderFor = Arc<dyn Fn(&str) -> Option<Arc<dyn LlmProvider>> + Send + Sync>;

pub async fn run_engagement(
    ctx: &mut EngagementCtx,
    provider_for: ProviderFor,
) -> anyhow::Result<EngagementResult> {
    let sem = Arc::new(Semaphore::new(ctx.budget.max_parallel));

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
             kind=endpoint, data={url, params})."
                .into(),
            ctx.discovery_turns,
            ctx.spend.clone(),
        )
        .await?;
        info!(turns = outcome.turns, reason = %outcome.finished_reason, "discovery done");
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
    let mut jobs: Vec<(EndpointTask, String, FindingClass)> = vec![];
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
            handles.push(tokio::spawn(async move {
                let _p = permit.acquire().await.unwrap();
                run_agent(provider, &reg, "solver", sys, objective, turns, spend).await
            }));
        }
    }
    info!(solver_runs, samples = ctx.samples, "solver wave spawned");

    // --- Validator intake (runs until shutdown signal) ---
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (tx_verified, mut rx_verified) = mpsc::channel::<(Finding, Verdict)>(256);
    let validators = ctx.validators.clone();
    let critic = provider_for("critic");
    let patterns = ctx.patterns.clone();
    let rejected = Arc::new(Mutex::new(0usize));
    let rej = rejected.clone();
    let intake = tokio::spawn(async move {
        async fn handle(
            f: Finding,
            validators: &ValidatorRegistry,
            rej: &Mutex<usize>,
            tx: &mpsc::Sender<(Finding, Verdict)>,
            critic: &Option<Arc<dyn LlmProvider>>,
            patterns: &Mutex<PatternLibrary>,
        ) {
            // Critic gate (LLM, advisory): slop filter before determinism.
            if let Some(c) = critic {
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
                        }
                        Verdict::Preview { .. } => {}
                    }
                    let _ = tx.send((f, verdict)).await;
                }
                None => {
                    *rej.lock().unwrap() += 1;
                    warn!(class=?f.class,"no validator for class — dropped");
                }
            }
        }

        let mut stopping = false;
        loop {
            if stopping {
                // Solvers are done — drain every queued finding, then exit.
                match findings_rx.try_recv() {
                    Ok(f) => handle(f, &validators, &rej, &tx_verified, &critic, &patterns).await,
                    Err(_) => break,
                }
                continue;
            }
            tokio::select! {
                _ = &mut stop_rx => stopping = true,
                maybe = findings_rx.recv() => {
                    match maybe {
                        Some(f) => handle(f, &validators, &rej, &tx_verified, &critic, &patterns).await,
                        None => break,
                    }
                }
            }
        }
    });

    let collect = tokio::spawn(async move {
        let mut verified = vec![];
        while let Some(fv) = rx_verified.recv().await {
            verified.push(fv);
        }
        verified
    });

    for h in handles {
        let _ = h.await;
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
            )
            .await;
        }
    }
    solver_runs += extra;

    // Grace window for in-flight validations, then shut intake down.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let _ = stop_tx.send(());
    let _ = intake.await;
    let verified = collect.await.unwrap_or_default();
    let rejected = *rejected.lock().unwrap();

    Ok(EngagementResult {
        verified,
        rejected,
        endpoints: tasks.len(),
        solver_runs,
    })
}
