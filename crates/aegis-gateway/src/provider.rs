//! Provider abstraction — implemented per backend (openai-compatible,
//! anthropic, any OpenAI-compatible endpoint incl. Ollama/vLLM/LM Studio).

use crate::message::Message;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("rate limited")]
    RateLimited,
    #[error("context length exceeded")]
    ContextLength,
    #[error("auth failed — check the API key")]
    Auth,
    #[error("no provider configured for role '{0}'")]
    NotConfigured(String),
}

/// Tool definition handed to providers (normalized to each API shape).
#[derive(Debug, Clone, Serialize)]
pub struct ToolSpec {
    #[serde(rename = "type")]
    pub kind: String, // "function"
    pub function: ToolFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolFunction {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub message: Message,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// One LLM backend. Implementations normalize tool-calling; models
/// without tool support fall back to text-parse mode upstream.
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn supports_tools(&self) -> bool;
    fn context_window(&self) -> u32;
    async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<Completion, ProviderError>;
}
