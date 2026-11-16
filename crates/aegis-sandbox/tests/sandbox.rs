use aegis_sandbox::*;

#[test]
fn allowlist_exact_and_suffix() {
    let a = Allowlist::new(&["api.target.com".into(), ".corp.io".into()]);
    assert!(a.allows("api.target.com"));
    assert!(a.allows("x.corp.io"));
    assert!(!a.allows("evil.com"));
    assert!(!a.allows("corp.io.evil.com"));
}

#[test]
fn empty_allowlist_denies_all() {
    let a = Allowlist::new(&[]);
    assert!(!a.allows("anything.com"));
}

#[tokio::test]
async fn oob_records_and_returns_hits() {
    let store = OobStore::default();
    let addr = run_oob_server("127.0.0.1:0".parse().unwrap(), store.clone()).await.unwrap();
    reqwest::get(format!("http://{addr}/tok123/cb")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let hits = store.hits_for("tok123");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].token, "tok123");
}
