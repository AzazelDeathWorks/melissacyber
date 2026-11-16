//! aegis-mcp — MCP tool server host.
//!
//! Exposes sandbox tools (terminal, http, browser, kg, oob, scope_check…)
//! to agents over MCP (rmcp). Also lets `aegis serve --mcp` expose the
//! whole harness to external agents (Claude Code, Cursor) as tools.

pub mod host;

pub use host::ToolServerHost;
