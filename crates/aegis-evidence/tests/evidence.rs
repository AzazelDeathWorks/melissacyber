use aegis_evidence::*;

#[test]
fn artifact_store_hashes_contents() {
    let mut s = ArtifactStore::default();
    let id = s.add("poc", "/tmp/a.txt".into(), b"hello");
    let a = &s.artifacts[0];
    assert_eq!(a.id, id);
    assert_eq!(a.sha256.len(), 64);
    assert_eq!(a.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

#[test]
fn markdown_report_lists_verified() {
    let entries = vec![(
        "sqli in q".to_string(), "high".to_string(), "sqli".to_string(),
        "GET /?q=1'".to_string(), "{}".to_string(),
    )];
    let md = render_markdown(uuid::Uuid::new_v4(), &entries);
    assert!(md.contains("sqli in q") && md.contains("1 verified"));
}
