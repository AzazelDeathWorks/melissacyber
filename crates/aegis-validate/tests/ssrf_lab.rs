//! Blind-SSRF validator against a metachar-gated sink (lab/hard_app.py
//! /ping?host= — only fetches when the value contains ;|$(` plus curl/wget).
//! Run with the lab up: PORT=8898 python3 lab/hard_app.py

use aegis_sandbox::{run_oob_server, Allowlist, OobStore};
use aegis_validate::validator::Validator;
use aegis_validate::verdict::Verdict;
use aegis_validate::{Finding, FindingClass, ProbeClient, Severity, SsrfValidator};

#[tokio::test]
async fn ssrf_metachar_gated_sink_produces_oob_hit() {
    let store = OobStore::default();
    let addr = run_oob_server("127.0.0.1:0".parse().unwrap(), store.clone())
        .await
        .unwrap();
    let probe = ProbeClient::new(None)
        .unwrap()
        .with_allow(Allowlist::new(&["127.0.0.1".into(), "localhost".into()]));
    let v = SsrfValidator {
        probe,
        oob: store,
        oob_base: format!("http://{addr}"),
    };
    let f = Finding {
        id: uuid::Uuid::new_v4(),
        class: FindingClass::Ssrf,
        severity: Severity::High,
        title: "blind ssrf on /ping host".into(),
        evidence: serde_json::json!({
            "request": {
                "method": "GET",
                "url": "http://127.0.0.1:8898/ping",
                "params": { "host": "x" }
            },
            "param": "host"
        }),
        verified: false,
    };
    let verdict = v.validate(&f).await;
    assert!(
        matches!(verdict, Verdict::Verified { .. }),
        "expected OOB-verified blind SSRF, got {verdict:?}"
    );
}
