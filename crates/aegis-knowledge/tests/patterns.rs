use aegis_knowledge::patterns::PatternLibrary;

#[test]
fn record_prior_fewshot_roundtrip() {
    let mut lib = PatternLibrary::default();
    lib.record("sqli", "GET /search?q=", "' OR '1'='1");
    lib.record("sqli", "GET /search?q=", "' OR '1'='1");
    lib.record("xss", "GET /r?q=", "<svg>");
    assert_eq!(lib.class_prior("sqli"), 2);
    assert_eq!(lib.class_prior("xss"), 1);
    assert_eq!(lib.class_prior("ssrf"), 0);
    let fs = lib.few_shot(5);
    assert!(fs.contains("sqli") && fs.contains("verified 2x"));

    let dir = std::env::temp_dir().join(format!("aegis-pat-{}", uuid::Uuid::new_v4()));
    let p = dir.join("patterns.jsonl");
    lib.save(&p).unwrap();
    let back = PatternLibrary::load(&p);
    assert_eq!(back.patterns.len(), 2);
    assert_eq!(back.class_prior("sqli"), 2);
}
