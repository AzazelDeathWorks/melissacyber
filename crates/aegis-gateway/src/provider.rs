//! Provider abstraction — implemented per backend (openai, anthropic,
//! gemini, openrouter, ollama/vLLM/any OpenAI-compatible endpoint).

use crate::message::Message;

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
}

/// One LLM backend. Implementations normalize tool-calling and structured
/// output; models without tool-call support fall back to text-parse mode
/// (HackingBuddyGPT dual-mode pattern).
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn supports_tools(&self) -> bool;
    fn context_window(&self) -> u32;
    async fn complete(
        &self,
        messages: &[Message],
    ) -> Result<Message, ProviderError>;
}
