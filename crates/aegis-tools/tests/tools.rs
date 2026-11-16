use aegis_kg::KnowledgeGraph;
use aegis_sandbox::Allowlist;
use aegis_tools::*;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[tokio::test]
async fn registry_filters_by_role() {
    let mut reg = ToolRegistry::default();
    reg.register(Arc::new(ScopeCheckTool { allow: Allowlist::new(&[]) }));
    let (tx, _rx) = mpsc::channel(4);
    reg.register(Arc::new(ValidatorSubmitTool { tx }));
    let names = |role: &str| -> Vec<String> {
        reg.for_role(role).iter().map(|t| t.spec().name.clone()).collect()
    };
    assert!(names("solver").contains(&"validator_submit".to_string()));
    assert!(names("solver").contains(&"scope_check".to_string()));
    assert!(names("discovery").contains(&"scope_check".to_string()));
}

#[tokio::test]
async fn validator_submit_sends_finding() {
    let (tx, mut rx) = mpsc::channel(4);
    let tool = ValidatorSubmitTool { tx };
    tool.call(json!({
        "class": "sqli", "severity": "high", "title": "t",
        "evidence": {"url": "http://x", "param": "q"}
    })).await.unwrap();
    let f = rx.recv().await.unwrap();
    assert!(matches!(f.class, aegis_validate::FindingClass::Sqli));
    assert!(!f.verified);
}

#[tokio::test]
async fn kg_write_then_query_roundtrips() {
    let kg = Arc::new(Mutex::new(KnowledgeGraph::default()));
    let w = KgTool { kg: kg.clone() };
    let q = KgQueryTool { kg };
    w.call(json!({"kind":"endpoint","label":"ep","data":{"url":"http://a","params":["x"]}}))
        .await.unwrap();
    let out = q.call(json!({"kind":"endpoint"})).await.unwrap();
    assert!(out.data.to_string().contains("http://a"));
}

#[tokio::test]
async fn scope_check_reports_in_and_out() {
    let t = ScopeCheckTool { allow: Allowlist::new(&["good.com".into(), ".corp.io".into()]) };
    assert_eq!(t.call(json!({"target":"good.com"})).await.unwrap().data["in_scope"], true);
    assert_eq!(t.call(json!({"target":"evil.net"})).await.unwrap().data["in_scope"], false);
    assert_eq!(t.call(json!({"target":"a.corp.io"})).await.unwrap().data["in_scope"], true);
    assert_eq!(t.call(json!({"target":"http://good.com/x"})).await.unwrap().data["in_scope"], true);
}
