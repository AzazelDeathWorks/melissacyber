//! End-to-end Faz 1 test: a deliberately vulnerable lab target on
//! localhost + scripted mock providers + the real engagement pipeline.
//!
//! Proves the core promise: solvers nominate, *non-AI validators verify*.
//! No LLM keys, no Docker needed — assertions are on real HTTP behavior.

use aegis_core::{run_engagement, Budget, EngagementCtx, ProviderFor};
use aegis_evidence::ArtifactStore;
use aegis_gateway::{LlmProvider, Message, MockProvider, Role, ToolCall};
use aegis_kg::KnowledgeGraph;
use aegis_sandbox::{Allowlist, HostBackend, OobStore, run_oob_server, SandboxBackend, SandboxSpec, BackendKind};
use aegis_scope::{Roe, Scope, Target, TargetKind};
use aegis_tools::*;
use aegis_validate::{CmdInjectionValidator, FilePathValidator, ProbeClient, SqliValidator, SsrfValidator, SstiValidator, ValidatorRegistry, Verdict, XssValidator};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Decode %XX and + in a query value (minimal, test-only).
fn urldecode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let h = u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'?');
                out.push(h as char);
                i += 3;
            }
            b'+' => {
                out.push(' ');
                i += 1;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// Vulnerable lab app:
///  GET /search?q=1     -> normal results
///  GET /search?q=1'    -> DB error signature (error-based SQLi)
///  GET /search?q=' OR '1'='1 -> returns all rows (boolean differential)
///  GET /search?q=' AND '1'='2 -> empty
///  GET /reflect?q=...  -> q reflected unescaped in HTML (XSS)
///  GET /fetch?url=...  -> server-side fetches url (SSRF -> OOB callback)
async fn vulnerable_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let line = req.lines().next().unwrap_or("");
                let path = line.split_whitespace().nth(1).unwrap_or("/");
                let (route, query) = path.split_once('?').unwrap_or((path, ""));
                let params: std::collections::HashMap<String, String> = query
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_string(), urldecode(v)))
                    .collect();

                let (status, body): (&str, String) = match route {
                    "/search" => {
                        let q = params.get("q").cloned().unwrap_or_default();
                        if q.ends_with('\'') && !q.contains("OR") && !q.contains("AND") && !q.contains("SLEEP") {
                            ("200 OK", "You have an error in your SQL syntax; check the manual".into())
                        } else if q.contains("OR '1'='1") {
                            ("200 OK", "results for 1: row1 row2 row3".into())
                        } else if q.contains("AND '1'='2") {
                            ("200 OK", "no results".into())
                        } else if q.contains("SLEEP(3)") {
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            ("200 OK", "results".into())
                        } else {
                            ("200 OK", "results for 1: row1 row2 row3".into())
                        }
                    }
                    "/reflect" => {
                        let q = params.get("q").cloned().unwrap_or_default();
                        ("200 OK", format!("<html><body>search: {q}</body></html>"))
                    }
                    "/exec" => {
                        let c = params.get("c").cloned().unwrap_or_default();
                        if c.contains("sleep 3") {
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            ("200 OK", "done".into())
                        } else if let Some(i) = c.find("echo ") {
                            ("200 OK", format!("out: {}", &c[i + 5..]))
                        } else {
                            ("200 OK", "ok".into())
                        }
                    }
                    "/tpl" => {
                        let n = params.get("name").cloned().unwrap_or_default();
                        if n.contains("{{") && n.contains('*') && n.contains("}}") {
                            ("200 OK", "result: 475906".into())
                        } else {
                            ("200 OK", format!("hello {n}"))
                        }
                    }
                    "/read" => {
                        let f = params.get("f").cloned().unwrap_or_default();
                        if f.contains("etc/passwd") {
                            ("200 OK", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon".into())
                        } else {
                            ("404 Not Found", "not found".into())
                        }
                    }
                    "/fetch" => {
                        if let Some(u) = params.get("url") {
                            let u = u.clone();
                            tokio::spawn(async move {
                                let _ = reqwest::get(&u).await;
                            });
                        }
                        ("200 OK", "fetched".into())
                    }
                    _ => ("404 Not Found", "nope".into()),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

fn script_discovery(url: String) -> Vec<Message> {
    vec![
        Message {
            role: Role::Assistant,
            content: "mapping".into(),
            tool_calls: vec![
                ToolCall {
                    id: "d1".into(),
                    name: "kg_write".into(),
                    arguments: json!({"kind":"endpoint","label":format!("{url}/search"),
                        "data":{"url":format!("{url}/search"),"params":["q"]}}),
                },
                ToolCall {
                    id: "d2".into(),
                    name: "kg_write".into(),
                    arguments: json!({"kind":"endpoint","label":format!("{url}/reflect"),
                        "data":{"url":format!("{url}/reflect"),"params":["q"]}}),
                },
                ToolCall {
                    id: "d3".into(),
                    name: "kg_write".into(),
                    arguments: json!({"kind":"endpoint","label":format!("{url}/fetch"),
                        "data":{"url":format!("{url}/fetch"),"params":["url"]}}),
                },
                ToolCall {
                    id: "d4".into(),
                    name: "kg_write".into(),
                    arguments: json!({"kind":"endpoint","label":format!("{url}/exec"),
                        "data":{"url":format!("{url}/exec"),"params":["c"]}}),
                },
                ToolCall {
                    id: "d5".into(),
                    name: "kg_write".into(),
                    arguments: json!({"kind":"endpoint","label":format!("{url}/tpl"),
                        "data":{"url":format!("{url}/tpl"),"params":["name"]}}),
                },
                ToolCall {
                    id: "d6".into(),
                    name: "kg_write".into(),
                    arguments: json!({"kind":"endpoint","label":format!("{url}/read"),
                        "data":{"url":format!("{url}/read"),"params":["f"]}}),
                },
            ],
            tool_call_id: None,
        },
    ]
}

/// Solver reads its objective (class + endpoint + param) and submits a
/// matching candidate finding — the validators do the real proving.
fn solver_decide(messages: &[Message]) -> Message {
    let objective = messages
        .iter()
        .rev()
        .find(|m| m.role == Role::User)
        .map(|m| m.content.clone())
        .unwrap_or_default();
    let class = ["Sqli", "Xss", "Ssrf", "CmdInjection", "Ssti", "FilePath"]
        .iter()
        .find(|c| objective.contains(**c))
        .copied()
        .unwrap_or("Other");
    let url = objective
        .lines()
        .find_map(|l| l.strip_prefix("Endpoint: "))
        .unwrap_or("")
        .to_string();
    let param = objective
        .lines()
        .find_map(|l| l.strip_prefix("Parameter: "))
        .map(|p| p.split(" (in:").next().unwrap_or(p).to_string())
        .unwrap_or_default();
    // Submit once — after a queued tool result, finish.
    if messages.iter().any(|m| m.role == Role::Tool && m.content.contains("queued")) {
        return Message {
            role: Role::Assistant,
            content: "submitted; done".into(),
            tool_calls: vec![],
            tool_call_id: None,
        };
    }
    if url.is_empty() || class == "Other" {
        return Message {
            role: Role::Assistant,
            content: "nothing to test".into(),
            tool_calls: vec![],
            tool_call_id: None,
        };
    }
    let class_str = match class {
        "CmdInjection" => "cmd",
        "FilePath" => "file_path",
        other => match other {
            "Sqli" => "sqli",
            "Xss" => "xss",
            "Ssrf" => "ssrf",
            "Ssti" => "ssti",
            _ => "other",
        },
    };
    Message {
        role: Role::Assistant,
        content: format!("testing {class}"),
        tool_calls: vec![ToolCall {
            id: "s1".into(),
            name: "validator_submit".into(),
            arguments: json!({
                "class": class_str,
                "severity": "high",
                "title": format!("{class} in param {param} at {url}"),
                "evidence": {"url": url, "param": param, "payload": "test"},
            }),
        }],
        tool_call_id: None,
    }
}

#[tokio::test]
async fn e2e_mock_engagement_verifies_real_vulns() {
    let target = vulnerable_target().await;
    let target_url = format!("http://{target}");
    let allow = Allowlist::new(&["127.0.0.1".into(), "localhost".into()]);

    let oob_store = OobStore::default();
    let oob_addr = run_oob_server("127.0.0.1:0".parse().unwrap(), oob_store.clone())
        .await
        .unwrap();
    let oob_base = format!("http://{oob_addr}");

    let (findings_tx, findings_rx) = mpsc::channel(256);
    let (spawn_tx, spawn_rx) = mpsc::channel(64);
    let kg = Arc::new(Mutex::new(KnowledgeGraph::default()));
    let spend = Arc::new(Mutex::new(Spend::default()));

    let backend: Arc<dyn SandboxBackend> = Arc::new(HostBackend);
    let handle = backend
        .provision(&SandboxSpec {
            backend: BackendKind::Docker,
            image: "host".into(),
            cpus: 1,
            mem_mb: 256,
            mounts: vec![],
            egress_allow: vec![],
        })
        .await
        .unwrap();

    let mut registry = ToolRegistry::default();
    registry.register(Arc::new(TerminalTool { backend: backend.clone(), handle: handle.clone() }));
    registry.register(Arc::new(HttpTool {
        client: reqwest::Client::new(),
        allow: allow.clone(),
        limiter: None,
        session: Arc::new(Mutex::new(aegis_tools::SessionStore::default())),
    }));
    registry.register(Arc::new(ScopeCheckTool { allow: allow.clone() }));
    registry.register(Arc::new(OobTool { store: oob_store.clone(), base_url: oob_base.clone() }));
    registry.register(Arc::new(KgTool { kg: kg.clone() }));
    registry.register(Arc::new(KgQueryTool { kg: kg.clone() }));
    registry.register(Arc::new(ValidatorSubmitTool { tx: findings_tx }));
    registry.register(Arc::new(SpawnAgentTool { tx: spawn_tx }));
    registry.register(Arc::new(BudgetTool { spend: spend.clone(), max_usd: Some(1.0) }));
    registry.register(Arc::new(ArtifactTool {
        dir: std::env::temp_dir().join("aegis-e2e-artifacts"),
        store: Arc::new(Mutex::new(ArtifactStore::default())),
    }));

    let mut validators = ValidatorRegistry::default();
    let probe = ProbeClient::new(None).unwrap().with_allow(allow.clone());
    validators.register(Arc::new(SqliValidator { probe: probe.clone() }));
    validators.register(Arc::new(XssValidator { probe: probe.clone() }));
    validators.register(Arc::new(SsrfValidator {
        probe: probe.clone(),
        oob: oob_store,
        oob_base,
    }));
    validators.register(Arc::new(CmdInjectionValidator { probe: probe.clone() }));
    validators.register(Arc::new(SstiValidator { probe: probe.clone() }));
    validators.register(Arc::new(FilePathValidator { probe }));

    let disc_url = target_url.clone();
    let provider_for: ProviderFor = Arc::new(move |role: &str| match role {
        "discovery" => Some(Arc::new(MockProvider::scripted(script_discovery(disc_url.clone())))
            as Arc<dyn LlmProvider>),
        "solver" => Some(Arc::new(MockProvider::with_decide(Box::new(solver_decide)))
            as Arc<dyn LlmProvider>),
        _ => None,
    });

    let scope = Scope {
        targets: vec![Target {
            kind: TargetKind::WebApp,
            value: target_url,
            workspace_path: None,
        }],
        egress_allow: vec!["127.0.0.1".into()],
        roe: Roe {
            authorization_statement: Some("test lab".into()),
            ..Roe::default()
        },
    };

    let mut ctx = EngagementCtx {
        scope,
        registry: Arc::new(registry),
        findings_rx,
        spawn_rx,
        validators: Arc::new(validators),
        kg,
        spend,
        budget: Budget {
            max_usd: Some(1.0),
            max_agents: 50,
            max_parallel: 8,
            wall_clock_secs: None,
            spent_usd: 0.0,
        },
        solver_turns: 6,
        discovery_turns: 6,
        artifacts_dir: std::env::temp_dir().join("aegis-e2e"),
        samples: 1,
        patterns: Arc::new(Mutex::new(aegis_knowledge::PatternLibrary::default())),
        prices: Default::default(),
        traces_dir: std::env::temp_dir().join("aegis-e2e-traces"),
        sweeps: false,
        skip_discovery: false,
        resume_keys: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        packs_dir: std::path::PathBuf::from("packs"),
        policy: None,
        bounty_sidecar: false,
        selfop: Arc::new(Mutex::new(aegis_knowledge::selfop::SelfOp::default())),
        probe: None,
    };

    let result = run_engagement(&mut ctx, provider_for).await.unwrap();

    let verified_classes: Vec<_> = result
        .verified
        .iter()
        .filter(|(_, v)| matches!(v, Verdict::Verified { .. }))
        .map(|(f, _)| f.class)
        .collect();

    for (f, v) in &result.verified {
        eprintln!("[result] {:?} {} -> {}", f.class, f.title,
            match v { Verdict::Verified{reproduction} => format!("VERIFIED {reproduction}"),
                Verdict::Rejected{reason} => format!("REJ {reason}"), _ => "preview".into() });
    }
    assert_eq!(result.endpoints, 6, "discovery should write 6 endpoints");
    assert_eq!(
        result.solver_runs, 37,
        "6 endpoints x 1 param x 6 classes + url->OpenRedirect affinity"
    );
    assert!(
        verified_classes.contains(&aegis_validate::FindingClass::Sqli),
        "sqli must be verified: {result:?}"
    );
    assert!(
        verified_classes.contains(&aegis_validate::FindingClass::Xss),
        "xss must be verified"
    );
    assert!(
        verified_classes.contains(&aegis_validate::FindingClass::Ssrf),
        "ssrf must be verified via OOB"
    );
    assert!(
        verified_classes.contains(&aegis_validate::FindingClass::CmdInjection),
        "cmd injection must be verified via canary echo"
    );
    assert!(
        verified_classes.contains(&aegis_validate::FindingClass::Ssti),
        "ssti must be verified via arithmetic evaluation"
    );
    assert!(
        verified_classes.contains(&aegis_validate::FindingClass::FilePath),
        "path traversal must be verified via file signature"
    );
}

#[tokio::test]
async fn scope_violation_is_blocked_at_tool_layer() {
    let allow = Allowlist::new(&["127.0.0.1".into()]);
    let tool = HttpTool {
        client: reqwest::Client::new(),
        allow,
        limiter: None,
        session: Arc::new(Mutex::new(aegis_tools::SessionStore::default())),
    };
    let out = tool.call(json!({"method":"GET","url":"http://evil.example.com/"})).await;
    assert!(out.is_err(), "out-of-scope host must be refused");
}

#[tokio::test]
async fn artifact_store_rejects_path_traversal() {
    let tool = ArtifactTool {
        dir: std::env::temp_dir().join("aegis-art-test"),
        store: Arc::new(Mutex::new(ArtifactStore::default())),
    };
    let out = tool.call(json!({"name":"../escape.txt","content":"x"})).await;
    assert!(out.is_err());
}
