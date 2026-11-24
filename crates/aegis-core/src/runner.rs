//! The agent execution loop: messages <-> provider <-> tool dispatch.
//! Every solver runs this loop with fresh context and a single objective.
//!
//! Hardening: transient provider errors retry with exponential backoff +
//! jitter; tool output is capped and wrapped in an untrusted-content
//! marker (the target's pages are attacker-controlled); USD spend is
//! tracked when a per-token price is configured.

use aegis_gateway::{Completion, LlmProvider, Message, ToolSpec as GwToolSpec};
use aegis_tools::{Spend, ToolRegistry};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Turn {
    pub role: String,
    pub content: String,
    pub tool_calls: usize,
}

#[derive(Debug)]
pub struct AgentOutcome {
    pub transcript: Vec<Message>,
    pub turns: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub finished_reason: String,
}

const TOOL_MAX_BYTES: usize = 32 * 1024;

fn to_gw_spec(t: &aegis_tools::ToolSpec) -> GwToolSpec {
    GwToolSpec {
        kind: "function".into(),
        function: aegis_gateway::provider::ToolFunction {
            name: t.name.clone(),
            description: t.description.clone(),
            parameters: t.schema.clone(),
        },
    }
}

fn transient(e: &aegis_gateway::provider::ProviderError) -> bool {
    let s = e.to_string().to_lowercase();
    s.contains("timeout")
        || s.contains("timed out")
        || s.contains("temporar")
        || s.contains("connection")
        || s.contains("reset")
        || s.contains("429")
        || s.contains("rate")
        || s.contains(" 502")
        || s.contains(" 503")
        || s.contains(" 529")
        || s.contains("overloaded")
}

/// Run one agent to completion: assistant turn -> dispatch tool calls ->
/// append results -> repeat. Ends on a no-tool-call reply or max_turns.
/// `price` = (usd per 1M input tokens, per 1M output tokens) if known.
pub async fn run_agent(
    provider: Arc<dyn LlmProvider>,
    registry: &ToolRegistry,
    role: &str,
    system: String,
    task: String,
    max_turns: u32,
    spend: Arc<Mutex<Spend>>,
    price: Option<(f64, f64)>,
    policy: Option<&aegis_tools::broker::PolicyBroker>,
) -> anyhow::Result<AgentOutcome> {
    let tools: Vec<GwToolSpec> = registry
        .for_role(role)
        .iter()
        .map(|t| to_gw_spec(&t.spec()))
        .collect();
    let reg_tools = registry.for_role(role);

    let mut messages = vec![Message::system(system), Message::user(task)];
    let mut turns = 0;
    let (mut in_tok, mut out_tok) = (0u64, 0u64);
    // Success-stall tracking: solvers sometimes find proof then keep
    // enumerating until max_turns without ever submitting (observed live:
    // FLAG{...} in tool output, zero validator_submit calls).
    let mut saw_submit = false;
    let mut proof_nudged = false;
    let mut last_nudge_turn = 0u32;

    loop {
        if turns >= max_turns {
            return Ok(AgentOutcome {
                transcript: messages,
                turns,
                input_tokens: in_tok,
                output_tokens: out_tok,
                finished_reason: "max_turns".into(),
            });
        }
        turns += 1;
        debug!(turn = turns, role, "agent turn");

        // Retry transient provider failures (rate limits, 5xx, timeouts).
        let Completion {
            message,
            input_tokens,
            output_tokens,
        } = {
            let mut attempt = 0u32;
            loop {
                match provider.complete(&messages, &tools).await {
                    Ok(c) => break c,
                    Err(e) => {
                        attempt += 1;
                        // ~9 attempts / ~4min worst case: survive sustained
                        // provider rate-limit windows instead of killing the
                        // solver (observed: 80/80 solvers died on a 429 storm).
                        if !transient(&e) || attempt > 8 {
                            return Err(anyhow::anyhow!(
                                "provider failed after {attempt} attempt(s): {e}"
                            ));
                        }
                        let jitter = (attempt as u64 * 137) % 500;
                        let wait = Duration::from_millis(
                            (500 * (1u64 << attempt)).min(60_000) + jitter,
                        );
                        warn!(attempt, ?wait, err = %e, "provider error — retrying");
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        };
        in_tok += input_tokens;
        out_tok += output_tokens;
        {
            let mut s = spend.lock().unwrap();
            s.input_tokens += input_tokens;
            s.output_tokens += output_tokens;
            if let Some((pi, po)) = price {
                s.usd += (input_tokens as f64 * pi + output_tokens as f64 * po) / 1e6;
            }
        }

        let calls = message.tool_calls.clone();
        messages.push(message);
        if calls.is_empty() {
            return Ok(AgentOutcome {
                transcript: messages,
                turns,
                input_tokens: in_tok,
                output_tokens: out_tok,
                finished_reason: "completed".into(),
            });
        }

        let mut saw_proof = false;
        for call in calls {
            if call.name == "validator_submit" {
                saw_submit = true;
            }
            let result = match reg_tools.iter().find(|t| t.spec().name == call.name) {
                Some(tool) => match policy {
                    Some(b) => match b.dispatch(tool, call.arguments.clone(), role).await {
                        Ok(o) => o.data.to_string(),
                        Err(e) => format!("tool error: {e}"),
                    },
                    None => match tool.call(call.arguments.clone()).await {
                        Ok(o) => o.data.to_string(),
                        Err(e) => format!("tool error: {e}"),
                    },
                },
                None => format!("unknown tool '{}'", call.name),
            };
            if result.contains("scope") && result.contains("Violation") {
                warn!(tool = call.name, "scope violation attempted");
            }
            if result.contains("FLAG{") || result.contains("flag{") {
                saw_proof = true;
            }
            let mut result = result;
            if result.len() > TOOL_MAX_BYTES {
                result.truncate(TOOL_MAX_BYTES);
                result.push_str("\n...[output truncated]");
            }
            // Tool output is attacker-controlled (target pages, shell
            // output). Wrap it so the model treats it as data, not orders.
            let wrapped = format!(
                "<untrusted_tool_output tool=\"{}\">{}</untrusted_tool_output>",
                call.name, result
            );
            messages.push(Message::tool_result(call.id, wrapped));
        }

        // Bank-the-win nudge: a solver that demonstrated a flaw but never
        // submits loses the finding at max_turns. Remind once on proof,
        // and periodically while it has never submitted.
        let submittable = matches!(role, "solver" | "bounty");
        if !saw_submit && submittable {
            let periodic = turns > 2 && turns - last_nudge_turn >= 8;
            if (saw_proof && !proof_nudged) || periodic {
                proof_nudged |= saw_proof;
                last_nudge_turn = turns;
                messages.push(Message::user(
                    "SYSTEM NUDGE: if any step produced a reproduction (flag, data dump, \
                     command output, auth bypass), call validator_submit NOW with that \
                     exact request as evidence — then keep hunting. Do not bank wins in \
                     your head; unsubmitted proof is lost at the turn cap."
                        .to_string(),
                ));
            }
        }
    }
}
