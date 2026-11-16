//! Provider-neutral message types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    /// Set on tool-result messages (provider wire id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(s: impl Into<String>) -> Self {
        Self { role: Role::System, content: s.into(), tool_calls: vec![], tool_call_id: None }
    }
    pub fn user(s: impl Into<String>) -> Self {
        Self { role: Role::User, content: s.into(), tool_calls: vec![], tool_call_id: None }
    }
    pub fn tool_result(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self { role: Role::Tool, content: content.into(), tool_calls: vec![], tool_call_id: Some(call_id.into()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}
