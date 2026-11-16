//! aegis-gateway — BYOK LLM gateway.
//!
//! Any provider, any model, per-role routing. Keys come from env/keyring
//! and never touch disk or logs. OpenAI-compatible endpoints (Ollama,
//! vLLM, LM Studio) make air-gapped use first-class.

pub mod anthropic;
pub mod message;
pub mod mock;
pub mod openai;
pub mod provider;
pub mod router;

pub use message::{Message, Role, ToolCall};
pub use mock::MockProvider;
pub use provider::{Completion, LlmProvider, ProviderError, ToolSpec};
pub use router::{build_provider, ModelRouter, RoleAssignment};
