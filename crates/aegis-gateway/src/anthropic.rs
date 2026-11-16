//! Anthropic Messages API provider.

use crate::message::{Message, Role, ToolCall};
use crate::provider::{Completion, LlmProvider, ProviderError, ToolSpec};
use reqwest::Client;
use serde_json::{json, Value};

pub struct AnthropicProvider {
    client: Client,
    pub name: String,
    pub model: String,
    pub api_key: String,
    pub context_window: u32,
}

impl AnthropicProvider {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            name: "anthropic".into(),
            model: model.into(),
            api_key: api_key.into(),
            context_window: 200_000,
        }
    }
}

fn to_wire(m: &Message) -> Option<Value> {
    match m.role {
        Role::System => None, // hoisted to top-level "system"
        Role::Tool => Some(json!({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": m.tool_call_id.clone().unwrap_or_default(),
                "content": m.content,
            }]
        })),
        Role::Assistant if !m.tool_calls.is_empty() => {
            let mut content = vec![];
            if !m.content.is_empty() {
                content.push(json!({"type": "text", "text": m.content}));
            }
            for tc in &m.tool_calls {
                content.push(json!({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.name,
                    "input": tc.arguments,
                }));
            }
            Some(json!({"role": "assistant", "content": content}))
        }
        Role::Assistant => Some(json!({"role": "assistant", "content": m.content})),
        Role::User => Some(json!({"role": "user", "content": m.content})),
    }
}

fn from_wire(v: &Value) -> Result<Message, ProviderError> {
    let mut text = String::new();
    let mut tool_calls = vec![];
    if let Some(blocks) = v["content"].as_array() {
        for b in blocks {
            match b["type"].as_str() {
                Some("text") => text.push_str(b["text"].as_str().unwrap_or("")),
                Some("tool_use") => tool_calls.push(ToolCall {
                    id: b["id"].as_str().unwrap_or("").to_string(),
                    name: b["name"].as_str().unwrap_or("").to_string(),
                    arguments: b["input"].clone(),
                }),
                _ => {}
            }
        }
    }
    Ok(Message {
        role: Role::Assistant,
        content: text,
        tool_calls,
        tool_call_id: None,
    })
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_tools(&self) -> bool {
        true
    }
    fn context_window(&self) -> u32 {
        self.context_window
    }

    async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<Completion, ProviderError> {
        let system = messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n\n");
        let wire_msgs: Vec<Value> = messages.iter().filter_map(to_wire).collect();

        let mut body = json!({
            "model": self.model,
            "max_tokens": 8192,
            "messages": wire_msgs,
        });
        if !system.is_empty() {
            body["system"] = json!(system);
        }
        if !tools.is_empty() {
            body["tools"] = tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.function.name,
                        "description": t.function.description,
                        "input_schema": t.function.parameters,
                    })
                })
                .collect::<Vec<_>>()
                .into();
        }

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            return Err(ProviderError::Auth);
        }
        if status == 429 {
            return Err(ProviderError::RateLimited);
        }
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|_| ProviderError::Unavailable(format!("bad json: {text}")))?;
        if v["type"].as_str() == Some("error") {
            return Err(ProviderError::Unavailable(format!(
                "anthropic error: {}",
                v["error"]["message"].as_str().unwrap_or("?")
            )));
        }
        let message = from_wire(&v)?;
        Ok(Completion {
            message,
            input_tokens: v["usage"]["input_tokens"].as_u64().unwrap_or(0),
            output_tokens: v["usage"]["output_tokens"].as_u64().unwrap_or(0),
        })
    }
}
