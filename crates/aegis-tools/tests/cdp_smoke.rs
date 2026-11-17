use aegis_tools::cdp::Cdp;
use aegis_tools::{BrowserSteerTool, Tool};
use aegis_sandbox::egress::Allowlist;

#[tokio::test]
async fn cdp_steering_smoke() {
    let mut c = Cdp::launch("/home/ubuntu/.local/bin/google-chrome").await.unwrap();
    c.navigate("http://127.0.0.1:8899/login", 3000).await.unwrap();
    let (dom, url) = c.snapshot().await.unwrap();
    assert!(url.contains("8899"));
    assert!(dom.len() > 10, "dom too small: {}", dom.len());
    let v = c.eval("document.title || 'untitled'").await.unwrap();
    assert!(v.is_string());
    let png = c.screenshot().await.unwrap();
    assert!(png.len() > 1000);
    c.close().await;
}

#[tokio::test]
async fn steer_tool_steps() {
    let tool = BrowserSteerTool {
        allow: Allowlist::new(&["127.0.0.1".to_string()]),
        chrome_path: "/home/ubuntu/.local/bin/google-chrome".into(),
        shots_dir: std::path::PathBuf::from("/tmp/aegis-test-shots"),
    };
    let r = tool
        .call(serde_json::json!({
            "url": "http://127.0.0.1:8899/",
            "steps": [
                {"eval": "document.title || 'x'"},
                {"click": "a"},
                {"wait_ms": 300},
                {"shot": "step1"},
                {"scroll": 500}
            ]
        }))
        .await
        .unwrap();
    let body = r.data;
    assert_eq!(body["steps"].as_array().unwrap().len(), 5);
    assert!(body["steps"][3]["saved"].as_bool().unwrap_or(false));
    assert!(std::path::Path::new("/tmp/aegis-test-shots/step1.png").exists());
}
