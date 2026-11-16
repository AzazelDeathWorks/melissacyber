use aegis_blue::*;
use aegis_validate::{Finding, FindingClass, Severity, Verdict};
use serde_json::json;
use uuid::Uuid;

fn verified_sqli() -> (Finding, Verdict) {
    (
        Finding {
            id: Uuid::new_v4(),
            class: FindingClass::Sqli,
            severity: Severity::High,
            title: "sqli in q".into(),
            evidence: json!({"url": "http://t.com/search", "param": "q"}),
            verified: false,
        },
        Verdict::Verified { reproduction: "GET /search?q=1'".into() },
    )
}

#[test]
fn sigma_rule_generated_and_matches_attack_request() {
    let (f, _) = verified_sqli();
    let rule = sigma_for(&f);
    assert!(rule.content.contains("cs-uri|contains: '/search'"));
    assert!(rule.content.contains("cs-uri-query|contains: 'q'"));
    assert!(rule.attck.contains(&"attack.t1190".to_string()));
    assert!(sigma_matches(&rule, "http://t.com/search?q=1'"));
    assert!(!sigma_matches(&rule, "http://t.com/other?x=1"));
}

#[test]
fn blue_loop_writes_detections_and_report() {
    let dir = std::env::temp_dir().join(format!("aegis-blue-{}", Uuid::new_v4()));
    let entries = vec![verified_sqli()];
    let rep = run_blue(&entries, &dir).unwrap();
    assert_eq!(rep.detections.len(), 1);
    assert_eq!(rep.replays.len(), 1);
    assert!(rep.replays[0].alert_fired, "sigma must fire on the attack request");
    assert!(!rep.replays[0].exploit_blocked, "unpatched target: exploit still works");
    assert_eq!(rep.patch_advisories.len(), 1);
    assert!(rep.patch_advisories[0].rationale.contains("prepared statements"));
    assert!(dir.join("blue_report.json").exists());
    assert!(std::fs::read_dir(dir.join("detections")).unwrap().count() == 1);
}
