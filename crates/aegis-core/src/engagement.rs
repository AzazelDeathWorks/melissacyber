//! Engagement orchestration: scope -> discovery -> solvers -> validators
//! -> verified findings -> report.

use crate::coordinator::{Coordinator, MVP_CLASSES};
use crate::prompts;
use crate::runner::run_agent;
use aegis_gateway::LlmProvider;
use aegis_kg::KnowledgeGraph;
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
    let mut handles = vec![];
    let mut solver_runs = 0usize;
    'outer: for task in &tasks {
        for param in &task.params {
            for class in MVP_CLASSES {
                if solver_runs >= ctx.budget.max_agents || ctx.budget.exhausted() {
                    warn!("budget/agent cap reached — frontier truncated");
                    break 'outer;
                }
                let Some(provider) = provider_for("solver") else {
                    anyhow::bail!("no provider for role 'solver'");
                };
                solver_runs += 1;
                let objective = Coordinator::solver_objective(task, param, class);
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
    }
    info!(solver_runs, "solver wave spawned");

    // --- Validator intake (runs until shutdown signal) ---
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (tx_verified, mut rx_verified) = mpsc::channel::<(Finding, Verdict)>(256);
    let validators = ctx.validators.clone();
    let rejected = Arc::new(Mutex::new(0usize));
    let rej = rejected.clone();
    let intake = tokio::spawn(async move {
        async fn handle(
            f: Finding,
            validators: &ValidatorRegistry,
            rej: &Mutex<usize>,
            tx: &mpsc::Sender<(Finding, Verdict)>,
        ) {
            match validators.get(&f.class) {
                Some(v) => {
                    let verdict = v.validate(&f).await;
                    match &verdict {
                        Verdict::Verified { .. } => info!(title=%f.title,"finding VERIFIED"),
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
                    Ok(f) => handle(f, &validators, &rej, &tx_verified).await,
                    Err(_) => break,
                }
                continue;
            }
            tokio::select! {
                _ = &mut stop_rx => stopping = true,
                maybe = findings_rx.recv() => {
                    match maybe {
                        Some(f) => handle(f, &validators, &rej, &tx_verified).await,
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
