use aegis_gateway::*;

#[test]
fn router_resolves_role_and_fallback() {
    let r = ModelRouter::from_yaml(
        "coordinator:\n  model: anthropic/claude-sonnet-4-5\n  fallback: [openai/gpt-4.1]\n\
         solver: openai/gpt-4.1-mini\n",
    )
    .unwrap();
    let a = r.resolve("coordinator").unwrap();
    assert_eq!(a.model, "anthropic/claude-sonnet-4-5");
    assert_eq!(a.fallback, vec!["openai/gpt-4.1"]);
    assert_eq!(r.resolve("solver").unwrap().model, "openai/gpt-4.1-mini");
    assert!(r.resolve("missing").is_none());
}

#[test]
fn build_provider_parses_specs() {
    // Keyless providers always construct.
    assert!(build_provider("ollama/llama3").is_ok());
    assert!(build_provider("custom|http://localhost:11434/v1/llama3").is_ok());
    // Keyed providers fail closed (Auth) when the env var is absent.
    std::env::remove_var("OPENAI_API_KEY");
    std::env::remove_var("ANTHROPIC_API_KEY");
    assert!(matches!(build_provider("openai/gpt-4.1"), Err(ProviderError::Auth)));
    assert!(matches!(build_provider("anthropic/x"), Err(ProviderError::Auth)));
    assert!(build_provider("bogus").is_err());
    assert!(build_provider("custom|/model").is_err());
}

#[tokio::test]
async fn mock_replays_script_then_ends() {
    let p = MockProvider::scripted(vec![Message {
        role: Role::Assistant,
        content: "one".into(),
        tool_calls: vec![ToolCall { id: "1".into(), name: "t".into(), arguments: serde_json::json!({}) }],
        tool_call_id: None,
    }]);
    let c1 = p.complete(&[], &[]).await.unwrap();
    assert_eq!(c1.message.tool_calls.len(), 1);
    let c2 = p.complete(&[], &[]).await.unwrap();
    assert!(c2.message.tool_calls.is_empty());
}
