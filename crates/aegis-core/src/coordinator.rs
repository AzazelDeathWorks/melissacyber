//! The persistent decision engine (XBOW coordinator pattern).
//!
//! Faz 1: deterministic orchestration — discovery wave -> endpoint sweep
//! -> bounded parallel solvers -> validator intake. PAG-based planning
//! (expected-utility frontier) grows here in Faz 2; the graph types are
//! already wired.

use crate::pag::AttackGraph;
use aegis_kg::NodeKind;
use aegis_validate::FindingClass;

/// One endpoint the discovery wave surfaced.
#[derive(Debug, Clone)]
pub struct EndpointTask {
    pub url: String,
    pub params: Vec<String>,
}

/// Solver classes spawned per parameterized endpoint (Faz 1 set).
/// Classes swept per parameterized endpoint (Faz 2 set).
pub const MVP_CLASSES: &[FindingClass] = &[
    FindingClass::Sqli,
    FindingClass::Xss,
    FindingClass::Ssrf,
    FindingClass::CmdInjection,
    FindingClass::Ssti,
    FindingClass::FilePath,
];

pub struct Coordinator {
    pub graph: AttackGraph,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            graph: AttackGraph::default(),
        }
    }

    /// Read endpoint nodes the discovery agents wrote into the KG.
    pub fn endpoint_tasks(kg: &aegis_kg::KnowledgeGraph) -> Vec<EndpointTask> {
        kg.nodes()
            .filter(|n| n.kind == NodeKind::Endpoint)
            .filter_map(|n| {
                let url = n.data["url"].as_str()?.to_string();
                let params = n.data["params"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|p| p.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                Some(EndpointTask { url, params })
            })
            .collect()
    }

    /// One solver objective per (endpoint, param, class).
    pub fn solver_objective(task: &EndpointTask, param: &str, class: &FindingClass) -> String {
        format!(
            "Objective: prove or disprove a {:?} vulnerability.\n\
             Endpoint: {}\nParameter: {}\n\
             Work the hypothesis end-to-end: craft inputs, observe\n\
             responses, and if you can demonstrate it, submit via\n\
             validator_submit with complete evidence. If disproven,\n\
             record what you tried in the KG.",
            class, task.url, param
        )
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}
