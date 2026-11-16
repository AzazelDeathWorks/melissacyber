//! aegis-gateway — BYOK LLM gateway.
//!
//! Any provider, any model, per-role routing. Keys come from env/keyring
//! and never touch disk or logs. OpenAI-compatible endpoints (Ollama,
//! vLLM, LM Studio) make air-gapped use first-class.

pub mod message;
pub mod provider;
pub mod router;

pub use message::{Message, Role, ToolCall};
pub use provider::{LlmProvider, ProviderError};
pub use router::{ModelRouter, RoleAssignment};
