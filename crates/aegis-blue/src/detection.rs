//! Deterministic detection engineering: verified finding -> Sigma rule.
//! No LLM in the loop — a rule is correct by construction or it isn't
//! generated at all.

use aegis_validate::{Finding, FindingClass};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleFormat {
    Sigma,
    Suricata,
    Yara,
}

/// TTP -> MITRE ATT&CK mapped detection artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub format: RuleFormat,
    pub attck: Vec<String>,
    pub content: String,
}

fn technique(class: FindingClass) -> &'static str {
    match class {
        FindingClass::Sqli | FindingClass::Nosqli => "attack.t1190", // Exploit Public-Facing App
        FindingClass::CmdInjection | FindingClass::Ssti => "attack.t1059", // Command & Scripting
        FindingClass::Xss => "attack.t1189", // Drive-by Compromise
        FindingClass::Ssrf => "attack.t1090", // Proxy
        FindingClass::FilePath => "attack.t1083", // File & Directory Discovery
        _ => "attack.t1190",
    }
}

/// Build a Sigma webserver-log rule matching the attack's request shape.
pub fn sigma_for(f: &Finding) -> DetectionRule {
    let url = f.evidence["url"].as_str().unwrap_or("");
    let param = f.evidence["param"].as_str().unwrap_or("");
    let path = reqwest::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.to_string());
    let class = format!("{:?}", f.class).to_lowercase();
    let attck = vec![technique(f.class).to_string()];
    let content = format!(
        "title: melissacyber {class} on {path}\n\
         id: {id}\n\
         status: experimental\n\
         description: Auto-generated from verified finding — {title}\n\
         logsource:\n  category: webserver\n\
         detection:\n  selection:\n    cs-uri|contains: '{path}'\n    cs-uri-query|contains: '{param}'\n  condition: selection\n\
         level: high\n\
         tags:\n  - {tech}\n",
        class = class,
        path = path,
        id = Uuid::new_v4(),
        title = f.title,
        param = param,
        tech = attck[0],
    );
    DetectionRule {
        id: Uuid::new_v4(),
        finding_id: f.id,
        format: RuleFormat::Sigma,
        attck,
        content,
    }
}

/// Evaluate the generated rule against a request (url) — the replay
/// matcher. Returns true when the rule would fire.
pub fn sigma_matches(rule: &DetectionRule, request_url: &str) -> bool {
    // Parse the two `|contains` patterns out of the rule body — the same
    // semantics the Sigma spec defines.
    let patterns: Vec<&str> = rule
        .content
        .lines()
        .filter(|l| l.contains("|contains:"))
        .filter_map(|l| l.split("'").nth(1))
        .collect();
    !patterns.is_empty() && patterns.iter().all(|p| request_url.contains(p))
}
