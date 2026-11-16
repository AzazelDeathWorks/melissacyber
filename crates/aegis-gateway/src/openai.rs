//! OpenAI-compatible provider: works for OpenAI, OpenRouter, Ollama,
//! vLLM, LM Studio, and any /v1/chat/completions endpoint.

use crate::message::{Message, Role, ToolCall};
use crate::provider::{Completion, LlmProvider, ProviderError, ToolSpec};
use reqwest::Client;
use serde_json::{json, Value};

pub struct OpenAiProvider {
    client: Client,
    pub name: String,
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub context_window: u32,
    pub tools: bool,
}

impl OpenAiProvider {
    /// `base_url` is the origin only (e.g. "http://localhost:11434/v1").
    pub fn new(
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        let model = model.into();
        Self {
            client: Client::new(),
            name: "openai-compatible".into(),
            model,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            context_window: 128_000,
            tools: true,
        }
    }
}

fn to_wire(m: &Message) -> Value {
    let mut v = json!({
        "role": match m.role {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        },
        "content": m.content,
    });
    if !m.tool_calls.is_empty() {
        v["tool_calls"] = serde_json::to_value(&m.tool_calls).unwrap_or_default();
    }
    if m.role == Role::Tool {
        if let Some(id) = m.tool_call_id.clone() {
            v["tool_call_id"] = json!(id);
        }
    }
    v
}

fn from_wire(v: &Value) -> Result<Message, ProviderError> {
    let msg = &v["choices"][0]["message"];
    let mut tool_calls = vec![];
    if let Some(calls) = msg["tool_calls"].as_array() {
        for c in calls {
            tool_calls.push(ToolCall {
                id: c["id"].as_str().unwrap_or("").to_string(),
                name: c["function"]["name"].as_str().unwrap_or("").to_string(),
                arguments: c["function"]["arguments"]
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(Value::Null),
            });
        }
    }
    Ok(Message {
        role: Role::Assistant,
        content: msg["content"].as_str().unwrap_or("").to_string(),
        tool_calls,
        tool_call_id: None,
    })
}

#[async_trait::async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_tools(&self) -> bool {
        self.tools
    }
    fn context_window(&self) -> u32 {
        self.context_window
    }

    async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<Completion, ProviderError> {
        let mut body = json!({
            "model": self.model,
            "messages": messages.iter().map(to_wire).collect::<Vec<_>>(),
        });
        if self.tools && !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools).unwrap_or_default();
        }

        let mut req = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .json(&body);
        if let Some(k) = &self.api_key {
            req = req.bearer_auth(k);
        }
        let resp = req.send().await.map_err(|e| {
            ProviderError::Unavailable(format!("request failed: {e}"))
        })?;

        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(ProviderError::Auth);
        }
        if status.as_u16() == 429 {
            return Err(ProviderError::RateLimited);
        }
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|_| ProviderError::Unavailable(format!("bad json: {text}")))?;
        if let Some(err) = v["error"].as_object() {
            return Err(ProviderError::Unavailable(format!(
                "provider error: {err:?}"
            )));
        }
        let message = from_wire(&v)?;
        let usage = v["usage"].clone();
        Ok(Completion {
            message,
            input_tokens: usage["prompt_tokens"].as_u64().unwrap_or(0),
            output_tokens: usage["completion_tokens"].as_u64().unwrap_or(0),
        })
    }
}
