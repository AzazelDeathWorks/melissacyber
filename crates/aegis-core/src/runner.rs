//! The agent execution loop: messages <-> provider <-> tool dispatch.
//! Every solver runs this loop with fresh context and a single objective.

use aegis_gateway::{Completion, LlmProvider, Message, ToolSpec as GwToolSpec};
use aegis_tools::{Spend, ToolRegistry};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
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

/// Run one agent to completion: assistant turn -> dispatch tool calls ->
/// append results -> repeat. Ends on a no-tool-call reply or max_turns.
pub async fn run_agent(
    provider: Arc<dyn LlmProvider>,
    registry: &ToolRegistry,
    role: &str,
    system: String,
    task: String,
    max_turns: u32,
    spend: Arc<Mutex<Spend>>,
) -> anyhow::Result<AgentOutcome> {
    let tools: Vec<GwToolSpec> = registry
        .for_role(role)
        .iter()
        .map(|t| to_gw_spec(&t.spec()))
        .collect();
    let reg_tools = registry.for_role(role);

    let mut messages = vec![
        Message::system(system),
        Message::user(task),
    ];
    let mut turns = 0;
    let (mut in_tok, mut out_tok) = (0u64, 0u64);

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

        let Completion {
            message,
            input_tokens,
            output_tokens,
        } = provider.complete(&messages, &tools).await?;
        in_tok += input_tokens;
        out_tok += output_tokens;
        {
            let mut s = spend.lock().unwrap();
            s.input_tokens += input_tokens;
            s.output_tokens += output_tokens;
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

        for call in calls {
            let result = match reg_tools.iter().find(|t| t.spec().name == call.name) {
                Some(tool) => match tool.call(call.arguments.clone()).await {
                    Ok(o) => o.data.to_string(),
                    Err(e) => format!("tool error: {e}"),
                },
                None => format!("unknown tool '{}'", call.name),
            };
            if result.contains("scope") && result.contains("Violation") {
                warn!(tool = call.name, "scope violation attempted");
            }
            messages.push(Message::tool_result(call.id, result));
        }
    }
}
