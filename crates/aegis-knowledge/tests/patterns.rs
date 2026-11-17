use aegis_knowledge::patterns::PatternLibrary;

#[test]
fn record_prior_fewshot_roundtrip() {
    let mut lib = PatternLibrary::default();
    lib.record("sqli", "victim/search?q=", "' OR '1'='1");
    lib.record("sqli", "victim/search?q=", "' OR '1'='1");
    lib.record("xss", "other/r?q=", "<svg>");
    assert_eq!(lib.class_prior("sqli"), 2);
    assert_eq!(lib.class_prior("xss"), 1);
    assert_eq!(lib.class_prior("ssrf"), 0);
    let fs = lib.few_shot_for("victim", 5);
    assert!(fs.contains("sqli") && fs.contains("verified 2x"));
    // host filter: "other" host's xss must not leak into victim's hints
    assert!(!fs.contains("xss"));
    let fs2 = lib.few_shot_for("other", 5);
    assert!(fs2.contains("xss") && !fs2.contains("sqli"));

    let dir = std::env::temp_dir().join(format!("aegis-pat-{}", uuid::Uuid::new_v4()));
    let p = dir.join("patterns.jsonl");
    lib.save(&p).unwrap();
    let back = PatternLibrary::load(&p);
    assert_eq!(back.patterns.len(), 2);
    assert_eq!(back.class_prior("sqli"), 2);
}
