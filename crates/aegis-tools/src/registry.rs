use crate::spec::Tool;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.spec().name.clone(), tool);
    }

    /// Tools visible to a given agent role.
    pub fn for_role(&self, role: &str) -> Vec<Arc<dyn Tool>> {
        self.tools
            .values()
            .filter(|t| t.spec().roles.iter().any(|r| r == role || r == "*"))
            .cloned()
            .collect()
    }
}
