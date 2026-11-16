//! Unit tests: agent loop, coordinator frontier, PAG graph, budget.

use aegis_core::*;
use aegis_gateway::{MockProvider, Message, Role, ToolCall};
use aegis_kg::{KnowledgeGraph, Node, NodeKind};
use aegis_tools::{Spend, Tool, ToolError, ToolOutput, ToolRegistry, ToolSpec};
use serde_json::json;
use std::sync::{Arc, Mutex};

struct Echo;
#[async_trait::async_trait]
impl Tool for Echo {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "echo".into(),
            description: "echo".into(),
            schema: json!({"type":"object","properties":{"s":{"type":"string"}}}),
            roles: vec!["*".into()],
        }
    }
    async fn call(&self, args: serde_json::Value) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput { ok: true, data: args.clone() })
    }
}

#[tokio::test]
async fn run_agent_dispatches_tools_then_completes() {
    let provider = Arc::new(MockProvider::scripted(vec![
        Message {
            role: Role::Assistant,
            content: "call echo".into(),
            tool_calls: vec![ToolCall {
                id: "c1".into(),
                name: "echo".into(),
                arguments: json!({"s":"hi"}),
            }],
            tool_call_id: None,
        },
    ]));
    let mut reg = ToolRegistry::default();
    reg.register(Arc::new(Echo));
    let spend = Arc::new(Mutex::new(Spend::default()));
    let out = run_agent(provider, &reg, "solver", "sys".into(), "task".into(), 8, spend)
        .await
        .unwrap();
    assert_eq!(out.finished_reason, "completed");
    assert_eq!(out.turns, 2);
    // transcript: system, user, assistant(call), tool result, assistant(done)
    assert_eq!(out.transcript.len(), 5);
    assert!(out.transcript[3].content.contains("hi"));
}

#[tokio::test]
async fn run_agent_unknown_tool_does_not_crash() {
    let provider = Arc::new(MockProvider::scripted(vec![Message {
        role: Role::Assistant,
        content: "x".into(),
        tool_calls: vec![ToolCall {
            id: "1".into(), name: "nonexistent".into(), arguments: json!({}),
        }],
        tool_call_id: None,
    }]));
    let reg = ToolRegistry::default();
    let spend = Arc::new(Mutex::new(Spend::default()));
    let out = run_agent(provider, &reg, "solver", "s".into(), "t".into(), 4, spend)
        .await
        .unwrap();
    assert!(out.transcript.iter().any(|m| m.content.contains("unknown tool")));
}

#[tokio::test]
async fn run_agent_respects_max_turns() {
    // decide: always emit a tool call -> never finishes naturally
    let provider = Arc::new(MockProvider::with_decide(Box::new(|_| Message {
        role: Role::Assistant,
        content: "loop".into(),
        tool_calls: vec![ToolCall { id: "x".into(), name: "echo".into(), arguments: json!({}) }],
        tool_call_id: None,
    })));
    let mut reg = ToolRegistry::default();
    reg.register(Arc::new(Echo));
    let spend = Arc::new(Mutex::new(Spend::default()));
    let out = run_agent(provider, &reg, "solver", "s".into(), "t".into(), 3, spend)
        .await
        .unwrap();
    assert_eq!(out.finished_reason, "max_turns");
    assert_eq!(out.turns, 3);
}

#[test]
fn coordinator_builds_tasks_from_kg() {
    let mut kg = KnowledgeGraph::default();
    for (url, params) in [
        ("http://a/s", vec!["q"]),
        ("http://a/f", vec!["u", "p"]),
        ("http://a/noparams", vec![]),
    ] {
        kg.add_node(Node {
            id: uuid::Uuid::new_v4(),
            kind: NodeKind::Endpoint,
            label: url.into(),
            data: json!({"url": url, "params": params}),
            provenance: None,
        });
    }
    let tasks = Coordinator::endpoint_tasks(&kg);
    assert_eq!(tasks.len(), 3);
    let o = Coordinator::solver_objective(&tasks[0], "q", &aegis_validate::FindingClass::Sqli);
    assert!(o.contains("Sqli") && o.contains("http://a/s") && o.contains("Parameter: q"));
}

#[test]
fn pag_next_frontier_picks_unsatisfied_step() {
    let g = AttackGraph::default();
    assert!(g.next_frontier(&[]).is_none());
}

#[test]
fn budget_exhaustion() {
    let b = Budget { max_usd: Some(1.0), max_agents: 10, max_parallel: 2, wall_clock_secs: None, spent_usd: 2.0 };
    assert!(b.exhausted());
    let b2 = Budget { max_usd: None, ..b };
    assert!(!b2.exhausted());
}
