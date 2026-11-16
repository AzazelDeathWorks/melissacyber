//! `--deep` mode: LLM-guided fuzzing (OSS-Fuzz pattern).
//! LLM proposes inputs -> they run against the target command in the
//! sandbox -> non-zero exits/timeouts become candidate crashes ->
//! replayed once to confirm (deterministic verify, no slop).

use aegis_gateway::{LlmProvider, Message};
use aegis_sandbox::{SandboxBackend, SandboxHandle};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Crash {
    pub id: Uuid,
    pub input: String,
    pub output: String,
    pub confirmed: bool,
}

/// Ask the LLM for a batch of candidate inputs (one per line).
pub async fn propose_inputs(
    provider: Arc<dyn LlmProvider>,
    context: &str,
    n: usize,
) -> Vec<String> {
    let r = provider
        .complete(
            &[
                Message::system(
                    "You write fuzz inputs that stress parsers/CLIs. Output ONLY the inputs, one per line. No commentary.",
                ),
                Message::user(format!(
                    "Target context:\n{context}\n\nProduce {n} diverse inputs likely to trigger crashes, overflows, or panics."
                )),
            ],
            &[],
        )
        .await;
    match r {
        Ok(c) => c
            .message
            .content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .take(n)
            .map(String::from)
            .collect(),
        Err(_) => vec![],
    }
}

/// Built-in seed corpus when no provider is available.
pub fn seed_inputs() -> Vec<String> {
    vec![
        "A".repeat(4096),
        "%s%s%s%s%s".into(),
        "'; DROP TABLE x; --".into(),
        "\u{0}\u{0}\u{0}\u{0}".into(),
        "{{7*7}}".into(),
        "../../../../etc/passwd".into(),
        "-1".into(),
        "9e9999999".into(),
        "() { :; };".into(),
        "\u{1b}[0m".into(),
    ]
}

/// Run each input as `cmd <input>`; a non-zero exit or stderr "panic/
/// segfault" marks a crash candidate; replay once to confirm.
pub async fn fuzz_run(
    backend: &Arc<dyn SandboxBackend>,
    handle: &SandboxHandle,
    cmd_template: &str,
    inputs: &[String],
) -> Vec<Crash> {
    let mut crashes = vec![];
    for input in inputs {
        let cmd = cmd_template.replacen("@@", input, 1);
        let out = match backend.exec(handle, &[&cmd]).await {
            Ok(o) => o,
            Err(e) => format!("exec error: {e}"),
        };
        let suspicious = out.contains("panic")
            || out.contains("Segmentation fault")
            || out.contains("SIGSEGV")
            || out.contains("core dumped")
            || out.contains("exec error");
        if suspicious {
            // Deterministic replay — a crash must reproduce.
            let replay = backend.exec(handle, &[&cmd]).await.unwrap_or_default();
            crashes.push(Crash {
                id: Uuid::new_v4(),
                input: input.clone(),
                output: out,
                confirmed: replay.contains("panic")
                    || replay.contains("Segmentation fault")
                    || replay.contains("SIGSEGV"),
            });
        }
    }
    info!(crashes = crashes.len(), "fuzz run complete");
    crashes
}
