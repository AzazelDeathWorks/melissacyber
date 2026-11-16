//! melissacyber — open-source AI security harness.
//! Built by the hydralabs deathworks ekibi.
//!
//! See `docs/design.md` for the architecture.

mod init_wizard;
mod run_pipeline;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aegis",
    about = "melissacyber — AI security harness by hydralabs deathworks ekibi",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Interactive setup: scope, ROE, budget, backend -> scope.yaml
    Init {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run an engagement end to end.
    Run {
        #[arg(long)]
        scope: PathBuf,
        #[arg(long, value_enum, default_value_t = ModeArg::Red)]
        mode: ModeArg,
        /// Aegis deep mode: LLM-guided fuzzing + code audit.
        #[arg(long)]
        deep: bool,
        /// USD spend cap.
        #[arg(long, default_value_t = 20.0)]
        budget: f64,
        /// Agent count cap.
        #[arg(long, default_value_t = 128)]
        max_agents: usize,
        /// Max parallel agents.
        #[arg(long, default_value_t = 8)]
        max_parallel: usize,
        /// Sandbox backend.
        #[arg(long, value_enum, default_value_t = BackendArg::Docker)]
        backend: BackendArg,
        /// Human-in-the-loop gates for dangerous actions.
        #[arg(long)]
        hitl: bool,
        /// Use the scripted mock provider (tests / demos, no API key).
        #[arg(long)]
        mock: bool,
        /// Engagement output dir.
        #[arg(long)]
        artifacts_dir: Option<PathBuf>,
        /// Sampling: solver variants per objective (sampling-and-verify).
        #[arg(long, default_value_t = 1)]
        samples: usize,
    },
    /// Interactive copilot mode: you drive, the harness executes + validates.
    Copilot {
        #[arg(long)]
        scope: PathBuf,
    },
    /// Serve melissacyber as an MCP server for other agents.
    Serve {
        #[arg(long)]
        mcp: bool,
        #[arg(long, default_value_t = 7420)]
        port: u16,
    },
    /// Run as a distributed worker (Faz 3).
    Worker {
        #[arg(long)]
        controller: Option<String>,
    },
    /// Run a benchmark suite (AutoPenBench / CVE-Bench / Cybench adapters).
    Bench {
        #[arg(long)]
        suite: String,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Replay a recorded engagement trace for purple/blue validation.
    Replay {
        #[arg(long)]
        engagement: String,
    },
    /// Render a report from an engagement's artifacts.
    Report {
        #[arg(long)]
        engagement: String,
        #[arg(long, default_value = "markdown")]
        format: String,
    },
    /// Manage domain packs and validator kits.
    Pack {
        #[command(subcommand)]
        sub: PackCmd,
    },
    /// Attacker-vs-defender self-play (Faz 4).
    Arena {
        #[arg(long)]
        rounds: usize,
    },
    /// Delta retest on change (CI).
    Watch {
        #[arg(long)]
        repo: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PackCmd {
    List,
    Install { name: String },
    New { name: String },
}

#[derive(Clone, Debug, ValueEnum)]
enum ModeArg {
    Red,
    Blue,
    Purple,
}

#[derive(Clone, Debug, ValueEnum)]
enum BackendArg {
    Docker,
    Gvisor,
    Firecracker,
    Host,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { target, out } => init_wizard::run(target, out).await?,
        Cmd::Run {
            scope,
            mode,
            deep,
            budget,
            max_agents,
            max_parallel,
            backend,
            hitl,
            mock,
            artifacts_dir,
            samples,
        } => {
            run_pipeline::run(run_pipeline::RunArgs {
                scope,
                mode,
                deep,
                budget,
                max_agents,
                max_parallel,
                backend,
                hitl,
                mock,
                artifacts_dir,
                samples,
            })
            .await?
        }
        Cmd::Copilot { scope } => {
            println!("copilot mode — interactive shell over {}", scope.display());
            println!("(Faz 2 deliverable; run `aegis run` for the autonomous path)");
        }
        Cmd::Serve { mcp, port } => {
            if mcp {
                println!("MCP server on :{port} — exposing pentest/validate tools (Faz 3)");
            }
        }
        Cmd::Worker { controller } => {
            println!("worker mode -> controller {controller:?} (Faz 3)");
        }
        Cmd::Bench { suite, limit } => {
            println!("bench {suite} limit={limit:?} — adapters land with Faz 1 tests");
        }
        Cmd::Replay { engagement } => {
            println!("replay engagement {engagement} (Faz 2)");
        }
        Cmd::Report { engagement, format } => {
            println!("report {engagement} -> {format}");
        }
        Cmd::Pack { sub } => match sub {
            PackCmd::List => {
                println!("domain packs (Faz 1): web\nroadmap: api network-ad cloud binary mobile smart-contract llm-target supply-chain saas-config iot");
            }
            PackCmd::Install { name } => println!("install pack {name}"),
            PackCmd::New { name } => println!("scaffold pack {name}"),
        },
        Cmd::Arena { rounds } => {
            println!("self-play arena, {rounds} rounds (Faz 4 — needs deterministic judge + GPU budget)");
        }
        Cmd::Watch { repo } => {
            println!("watch {repo:?} — delta retest on change (Faz 3)");
        }
    }
    Ok(())
}
