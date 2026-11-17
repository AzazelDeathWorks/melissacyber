use crate::spec::Tool;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Registry with interior mutability — meta-tooling (define_tool) can add
/// agent-authored tools while the engagement is running.
#[derive(Default)]
pub struct ToolRegistry {
    tools: Mutex<BTreeMap<String, Arc<dyn Tool>>>,
}

impl ToolRegistry {
    pub fn register(&self, tool: Arc<dyn Tool>) {
        self.tools
            .lock()
            .unwrap()
            .insert(tool.spec().name.clone(), tool);
    }

    /// Tools visible to a given agent role.
    pub fn for_role(&self, role: &str) -> Vec<Arc<dyn Tool>> {
        self.tools
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.spec().roles.iter().any(|r| r == role || r == "*"))
            .cloned()
            .collect()
    }
}
