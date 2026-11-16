use aegis_scope::*;

#[test]
fn scope_yaml_roundtrip() {
    let s = Scope {
        targets: vec![Target { kind: TargetKind::WebApp, value: "http://t".into(), workspace_path: None }],
        egress_allow: vec!["t.com".into()],
        roe: Roe::default(),
    };
    let y = serde_yaml::to_string(&s).unwrap();
    let back: Scope = serde_yaml::from_str(&y).unwrap();
    assert_eq!(back.targets[0].value, "http://t");
}

#[test]
fn roe_is_deny_by_default() {
    let r = Roe::default();
    assert!(!r.allow_dos && !r.allow_exfil && !r.allow_persistence
        && !r.allow_bruteforce && !r.allow_social_engineering);
    assert!(r.hitl_required);
}
