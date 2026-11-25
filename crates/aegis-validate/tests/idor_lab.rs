//! IDOR validator against the gauntlet lab (/orders/<id> — REST object id
//! in the path, no query string). Evidence shaped exactly as solvers
//! submit it: no `in` field, object id inside the URL path.

use aegis_sandbox::Allowlist;
use aegis_validate::validator::Validator;
use aegis_validate::verdict::Verdict;
use aegis_validate::web2::IdorValidator;
use aegis_validate::{Finding, FindingClass, ProbeClient, Severity};

#[tokio::test]
async fn idor_path_object_id_verifies() {
    let probe = ProbeClient::new(None)
        .unwrap()
        .with_allow(Allowlist::new(&["127.0.0.1".into(), "localhost".into()]));
    let v = IdorValidator { probe };
    let f = Finding {
        id: uuid::Uuid::new_v4(),
        class: FindingClass::AuthzIdor,
        severity: Severity::Medium,
        title: "idor on /orders".into(),
        evidence: serde_json::json!({
            "expect": "bob: 1x gadget (PRIVATE)",
            "param": "id",
            "payload": "1002",
            "request": {
                "method": "GET",
                "url": "http://127.0.0.1:8897/orders/1002",
                "params": {},
                "headers": {},
                "body": ""
            }
        }),
        verified: false,
    };
    let verdict = v.validate(&f).await;
    assert!(
        matches!(verdict, Verdict::Verified { .. }),
        "expected IDOR verified, got {verdict:?}"
    );
}
