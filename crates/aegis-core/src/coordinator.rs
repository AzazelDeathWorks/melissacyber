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

    /// Map a finding class to the validator name used in packs/*.yaml.
    fn pack_validator_name(c: &FindingClass) -> &'static str {
        match c {
            FindingClass::Sqli => "sqli",
            FindingClass::Xss => "xss",
            FindingClass::Ssrf => "ssrf",
            FindingClass::CmdInjection => "cmd_injection",
            FindingClass::Ssti => "ssti",
            FindingClass::FilePath => "file_path",
            FindingClass::OpenRedirect => "open_redirect",
            FindingClass::HostHeader => "host_header",
            FindingClass::Secrets => "secrets",
            FindingClass::Csrf => "csrf",
            FindingClass::AuthzIdor => "idor",
            FindingClass::FileUpload => "file_upload",
            FindingClass::Deserialization => "deserialization",
            FindingClass::Race => "race",
            FindingClass::BusinessLogic => "business_logic",
            _ => "",
        }
    }

    /// Domain-pack hint line for a class: which packs cover it and which
    /// agent playbooks they ship. Injected into solver objectives so pack
    /// knowledge actually reaches solvers.
    pub fn pack_hint(packs_dir: &std::path::Path, c: &FindingClass) -> String {
        let vn = Self::pack_validator_name(c);
        if vn.is_empty() {
            return String::new();
        }
        let mut hits = vec![];
        if let Ok(rd) = std::fs::read_dir(packs_dir) {
            for e in rd.flatten() {
                let Ok(txt) = std::fs::read_to_string(e.path()) else { continue };
                if !txt.contains("validators:") || !txt.contains(vn) {
                    continue;
                }
                let name = txt
                    .lines()
                    .find(|l| l.starts_with("name:"))
                    .map(|l| l[5..].trim().to_string())
                    .unwrap_or_default();
                let agents = txt
                    .lines()
                    .find(|l| l.trim_start().starts_with("agents:"))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_default();
                hits.push(format!("{name} ({agents})"));
            }
        }
        if hits.is_empty() {
            return String::new();
        }
        format!("\nDomain packs covering this class: {}.", hits.join(", "))
    }

    /// One solver objective per (endpoint, param, class).
    pub fn solver_objective(task: &EndpointTask, param: &Param, class: &FindingClass) -> String {
        format!(
            "Objective: prove or disprove a {:?} vulnerability.\n\
             Endpoint: {}\nParameter: {} (in: {})\n\
             First call kg_query (contains the endpoint URL) to reuse\n\
             what sibling solvers already found or disproved here.\n\
             Work the hypothesis end-to-end: craft inputs, observe\n\
             responses, and if you can demonstrate it, submit via\n\
             validator_submit with complete evidence. If disproven,\n\
             record a 'disproof: <class> on <endpoint>' note via kg_write\n\
             and FINISH — do not burn remaining turns on a dead end.",
            class, task.url, param.name, param.r#in
        )
    }

    /// Param-less sweeps: classes that apply to whole endpoints/hosts
    /// (info disclosure, CORS) — no parameter needed.
    pub const SWEEP_CLASSES: &[FindingClass] = &[
        FindingClass::InfoDisclosure,
        FindingClass::Cors,
        FindingClass::HostHeader,
        FindingClass::Secrets,
        FindingClass::Csrf,
        FindingClass::FileUpload,
        FindingClass::BusinessLogic,
        FindingClass::OpenRedirect,
        FindingClass::SessionJwt,
        FindingClass::Authn,
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
