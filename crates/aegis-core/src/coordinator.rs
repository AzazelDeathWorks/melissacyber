//! The persistent decision engine (XBOW coordinator pattern).
//!
//! Faz 1: deterministic orchestration — discovery wave -> endpoint sweep
//! -> bounded parallel solvers -> validator intake. PAG-based planning
//! (expected-utility frontier) grows here in Faz 2; the graph types are
//! already wired.

use crate::pag::AttackGraph;
use aegis_kg::NodeKind;
use aegis_validate::FindingClass;

/// One injectable parameter with where it lives in the request.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    /// query | form | body | json | header | path — hint for solvers.
    pub r#in: String,
}

/// One endpoint the discovery wave surfaced.
#[derive(Debug, Clone)]
pub struct EndpointTask {
    pub url: String,
    pub params: Vec<Param>,
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
                            // Models write params as strings or as
                            // {name,in,confirmed} objects — take either.
                            .filter_map(|p| {
                                p.as_str()
                                    .map(|n| Param {
                                        name: n.to_string(),
                                        r#in: "query".into(),
                                    })
                                    .or_else(|| {
                                        p["name"].as_str().map(|n| Param {
                                            name: n.to_string(),
                                            r#in: p["in"]
                                                .as_str()
                                                .unwrap_or("query")
                                                .to_string(),
                                        })
                                    })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(EndpointTask { url, params })
            })
            .collect()
    }

    /// One solver objective per (endpoint, param, class).
    pub fn solver_objective(task: &EndpointTask, param: &Param, class: &FindingClass) -> String {
        format!(
            "Objective: prove or disprove a {:?} vulnerability.\n\
             Endpoint: {}\nParameter: {} (in: {})\n\
             Work the hypothesis end-to-end: craft inputs, observe\n\
             responses, and if you can demonstrate it, submit via\n\
             validator_submit with complete evidence. If disproven,\n\
             record what you tried in the KG.",
            class, task.url, param.name, param.r#in
        )
    }

    /// Param-less sweeps: classes that apply to whole endpoints/hosts
    /// (info disclosure, CORS) — no parameter needed.
    pub const SWEEP_CLASSES: &[FindingClass] = &[
        FindingClass::InfoDisclosure,
        FindingClass::Cors,
    ];

    /// Jobs for endpoints discovered with no injectable params, plus a
    /// per-endpoint info/cors sweep regardless.
    pub fn sweep_objective(url: &str, class: &FindingClass) -> String {
        format!(
            "Objective: prove or disprove a {:?} issue.\n\
             Endpoint: {}\n\
             Fetch the endpoint, inspect headers/body, and submit via\n\
             validator_submit with evidence {url} (and an 'expect' marker\n\
             for info_disclosure) if demonstrable.",
            class, url
        )
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}
