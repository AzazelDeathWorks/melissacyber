//! Scripted provider for tests: replays canned responses, or runs a
//! user-supplied decision function. No network, no keys.

use crate::message::Message;
use crate::provider::{Completion, LlmProvider, ProviderError, ToolSpec};
use std::sync::Mutex;

type DecideFn = Box<dyn Fn(&[Message]) -> Message + Send + Sync>;

pub struct MockProvider {
    script: Mutex<Vec<Message>>,
    decide: Option<DecideFn>,
    pub model: String,
}

impl MockProvider {
    /// Replays `script` messages in order; when exhausted, returns a
    /// plain assistant message (ends tool loops).
    pub fn scripted(script: Vec<Message>) -> Self {
        Self {
            script: Mutex::new(script),
            decide: None,
            model: "mock".into(),
        }
    }

    /// Custom logic — e.g. "if asked to probe, call http_client".
    pub fn with_decide(f: DecideFn) -> Self {
        Self {
            script: Mutex::new(vec![]),
            decide: Some(f),
            model: "mock".into(),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_tools(&self) -> bool {
        true
    }
    fn context_window(&self) -> u32 {
        1_000_000
    }

    async fn complete(
        &self,
        messages: &[Message],
        _tools: &[ToolSpec],
    ) -> Result<Completion, ProviderError> {
        let message = if let Some(f) = &self.decide {
            f(messages)
        } else {
            let mut s = self.script.lock().unwrap();
            if s.is_empty() {
                Message {
                    role: crate::message::Role::Assistant,
                    content: "done".into(),
                    tool_calls: vec![],
                    tool_call_id: None,
                }
            } else {
                s.remove(0)
            }
        };
        Ok(Completion {
            message,
            input_tokens: 0,
            output_tokens: 0,
        })
    }
}
