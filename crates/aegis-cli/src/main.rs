//! melissacyber — CLI entry point.
//!
//! CLI-first: `aegis init` -> scope.yaml, `aegis run --mode red|blue|purple`,
//! `aegis serve --mcp`, `aegis worker`, `aegis bench`, `aegis copilot`…

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "melissacyber — open-source autonomous cyber harness (red + blue), by hydralabs deathworks",
    long_about = "Autonomous security testing for systems you own or are authorized to test. \
                  Deterministic validation, network-level scope enforcement, BYOK models."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Interactive wizard: writes scope.yaml (targets, RoE, budget, authorization).
    Init,
    /// Run an engagement.
    Run {
        /// Target or workspace path (overrides scope.yaml when given).
        #[arg(long)]
        target: Option<String>,
        #[arg(long, value_enum, default_value = "red")]
        mode: ModeArg,
        /// Deep source-code mode: LLM-guided fuzz harness generation.
        #[arg(long)]
        deep: bool,
        /// Human-in-the-loop approval gate for dangerous actions.
        #[arg(long)]
        hitl: Option<bool>,
        /// Hard spend cap in USD.
        #[arg(long)]
        budget: Option<f64>,
        /// Isolation backend for the attack box.
        #[arg(long, value_enum, default_value = "docker")]
        backend: BackendArg,
    },
    /// Interactive co-drive: you and the coordinator plan together.
    Copilot,
    /// Expose the harness as an API/MCP server for IDEs and other agents.
    Serve {
        #[arg(long)]
        mcp: bool,
        #[arg(long, default_value = "127.0.0.1:7357")]
        bind: String,
    },
    /// Join a distributed engagement as a solver worker.
    Worker {
        #[arg(long)]
        join: String,
    },
    /// Run benchmark suites (Cybench, AutoPenBench, NYU CTF, CyberGym…).
    Bench {
        #[arg(long)]
        suite: String,
    },
    /// Re-run a finding's PoC.
    Replay {
        finding: String,
    },
    /// Render engagement report (md/pdf/sarif/html).
    Report {
        #[arg(long, default_value = "markdown")]
        format: String,
    },
    /// Manage domain packs and plugins.
    Pack {
        #[arg(value_parser = ["list", "install", "build"])]
        action: String,
        name: Option<String>,
    },
    /// Self-play training arena (attacker vs defender agents).
    Arena,
    /// Watch a target and run delta-pentests on change.
    Watch,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => println!("aegis init: scope/RoE wizard — Faz 1"),
        Cmd::Run { mode, .. } => println!("aegis run --mode {:?}: engagement loop — Faz 1", mode),
        Cmd::Copilot => println!("aegis copilot: human + coordinator co-drive — Faz 2"),
        Cmd::Serve { mcp, bind } => println!("aegis serve (mcp={mcp}) on {bind} — Faz 3"),
        Cmd::Worker { join } => println!("aegis worker --join {join} — Faz 3"),
        Cmd::Bench { suite } => println!("aegis bench --suite {suite} — Faz 1 runner skeleton"),
        Cmd::Replay { finding } => println!("aegis replay {finding} — Faz 2"),
        Cmd::Report { format } => println!("aegis report --format {format} — Faz 1"),
        Cmd::Pack { action, name } => println!("aegis pack {action} {:?} — Faz 3", name),
        Cmd::Arena => println!("aegis arena: self-play training ground — Faz 4"),
        Cmd::Watch => println!("aegis watch: continuous delta-pentest — Faz 3"),
    }
    Ok(())
}
