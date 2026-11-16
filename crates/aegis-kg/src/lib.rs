//! aegis-kg — engagement knowledge graph + episodic memory.
//!
//! Single shared structure all agents read/write (ChainPen's SMA).
//! Nodes: Asset, Endpoint, Param, Tech, Fact, Finding, Evidence.
//! Every fact carries provenance — who learned it and how. Context-rot
//! kills ~42% of naive agent runs; the KG is the fix.

pub mod graph;
pub mod node;

pub use graph::KnowledgeGraph;
pub use node::{EdgeKind, Node, NodeId, NodeKind, Provenance};
