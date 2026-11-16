use crate::node::{EdgeKind, Node, NodeId};
use std::collections::BTreeMap;

/// SQLite/sled-backed in Faz 1; Neo4j adapter later.
#[derive(Default)]
pub struct KnowledgeGraph {
    nodes: BTreeMap<NodeId, Node>,
    edges: Vec<(NodeId, NodeId, EdgeKind)>,
}

impl KnowledgeGraph {
    pub fn add_node(&mut self, n: Node) -> NodeId {
        let id = n.id;
        self.nodes.insert(id, n);
        id
    }

    pub fn link(&mut self, a: NodeId, b: NodeId, kind: EdgeKind) {
        self.edges.push((a, b, kind));
    }

    /// Untested surface the coordinator turns into solver tasks.
    pub fn frontier(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }
}
