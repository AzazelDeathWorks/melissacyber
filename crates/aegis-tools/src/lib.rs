//! aegis-tools — agent-facing tool layer.
//!
//! ~15 curated wrappers per agent (not all ~120 Kali tools): interface
//! quality beats tool count (Project Naptime principle #3). Every tool
//! speaks structured I/O and is sandbox-scoped.

pub mod registry;
pub mod spec;

pub use registry::ToolRegistry;
pub use spec::{Tool, ToolError, ToolOutput, ToolSpec};
