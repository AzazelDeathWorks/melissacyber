use aegis_mcp::{serve, McpState};
use aegis_sandbox::{Allowlist, OobStore, SandboxBackend};
use aegis_validate::{FindingClass, SsrfValidator, ValidatorRegistry};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

async fn post(url: &str, body: serde_json::Value) -> serde_json::Value {
    reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_and_worker_queue_roundtrip() {
    let oob = OobStore::default();
    let _ = aegis_sandbox::run_oob_server("127.0.0.1:0".parse().unwrap(), oob.clone()).await.unwrap();
    let mut validators = ValidatorRegistry::default();
    let probe = aegis_validate::ProbeClient::new(None).unwrap();
    validators.register(Arc::new(SsrfValidator {
        probe,
        oob: oob.clone(),
        oob_base: "http://127.0.0.1:9".into(),
    }));
    let state = Arc::new(McpState {
        allow: Allowlist::new(&["target.local".into()]),
        validators: Arc::new(validators),
        oob,
        oob_base: "http://127.0.0.1:9".into(),
        jobs: Mutex::new(Default::default()),
        results: Mutex::new(vec![]),
    });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(serve(state.clone(), addr));

    // MCP initialize + tools/list + scope check
    let init = post(&format!("http://{addr}/mcp"), serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"initialize"})).await;
    assert!(init["result"]["serverInfo"]["name"].as_str().unwrap().contains("melissacyber"));
    let tools = post(&format!("http://{addr}/mcp"), serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
    assert!(tools["result"]["tools"].as_array().unwrap().len() >= 3);
    let sc = post(&format!("http://{addr}/mcp"), serde_json::json!({
        "jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"aegis_scope_check","arguments":{"host":"target.local"}}})).await;
    assert!(sc["result"]["content"][0]["text"].as_str().unwrap().contains("true"));

    // worker queue: enqueue job, dequeue it, post result, list results
    let b = aegis_sandbox::HostBackend;
    let h = b.provision(&aegis_sandbox::SandboxSpec {
        backend: aegis_sandbox::BackendKind::Docker,
        image: "host".into(),
        cpus: 1,
        mem_mb: 64,
        mounts: vec![],
        egress_allow: vec![],
    }).await.unwrap();
    let job = serde_json::json!({"objective":"test task"});
    b.exec(&h, &[&format!("curl -s -X POST http://{addr}/jobs -d '{}'", job.to_string().replace('\'',"'\\''"))]).await.unwrap();
    let got = b.exec(&h, &[&format!("curl -s http://{addr}/jobs")]).await.unwrap();
    assert!(got.contains("test task"));
    b.exec(&h, &[&format!("curl -s -X POST http://{addr}/results -d '{{\"status\":\"done\"}}'")]).await.unwrap();
    let results = b.exec(&h, &[&format!("curl -s http://{addr}/results/list")]).await.unwrap();
    assert!(results.contains("done"));
}
