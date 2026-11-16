//! The closed red->blue loop ("offensive vaccine"):
//! verified finding -> detection rule -> replay -> alert proof.
//!
//! Patch generation stays advisory in Faz 2 (LLM-optional); the
//! detection+replay half is fully deterministic.

use crate::detection::{sigma_for, sigma_matches, DetectionRule};
use crate::patch::PatchProposal;
use crate::replay::ReplayResult;
use aegis_validate::{Finding, FindingClass, Verdict};
use std::path::{Path, PathBuf};

#[derive(Debug, serde::Serialize)]
pub struct BlueReport {
    pub detections: Vec<DetectionRule>,
    pub replays: Vec<ReplayResult>,
    pub patch_advisories: Vec<PatchProposal>,
}

fn remediation(f: &Finding) -> String {
    match f.class {
        FindingClass::Sqli | FindingClass::Nosqli =>
            "Parameterize the query (prepared statements); never interpolate input into SQL.".into(),
        FindingClass::CmdInjection =>
            "Remove shell invocation; use execve-style arg arrays + strict input allowlists.".into(),
        FindingClass::Ssti =>
            "Render templates with a sandboxed engine; never evaluate user input as template source.".into(),
        FindingClass::Xss =>
            "Context-aware output encoding (HTML attr/body/JS); add a strict CSP.".into(),
        FindingClass::Ssrf =>
            "Egress allowlist on the fetcher; resolve+pin DNS; block RFC1918/link-local/metadata ranges.".into(),
        FindingClass::FilePath =>
            "Resolve paths against a fixed base dir; reject '..' and absolute paths after canonicalization.".into(),
        _ => "See finding evidence; add input validation and least-privilege boundaries.".into(),
    }
}

/// Run the blue half on verified findings. Deterministic — no provider
/// needed. Writes detections/*.yml and blue_report.json.
pub fn run_blue(
    verified: &[(Finding, Verdict)],
    artifacts_dir: &Path,
) -> anyhow::Result<BlueReport> {
    let det_dir = artifacts_dir.join("detections");
    std::fs::create_dir_all(&det_dir)?;

    let mut report = BlueReport {
        detections: vec![],
        replays: vec![],
        patch_advisories: vec![],
    };

    for (f, verdict) in verified {
        if !matches!(verdict, Verdict::Verified { .. }) {
            continue;
        }
        // 1. Detection rule (deterministic).
        let rule = sigma_for(f);
        let rule_path: PathBuf = det_dir.join(format!("{}.yml", rule.id));
        std::fs::write(&rule_path, &rule.content)?;

        // 2. Replay: does the rule catch the recorded attack request?
        let url = f.evidence["url"].as_str().unwrap_or("");
        let param = f.evidence["param"].as_str().unwrap_or("");
        let attack_request = format!("{url}?{param}=");
        let alert_fired = sigma_matches(&rule, &attack_request);
        report.replays.push(ReplayResult {
            finding_id: f.id,
            exploit_blocked: false, // target unpatched — honest answer
            alert_fired,
        });
        report.detections.push(rule);

        // 3. Patch advisory (fix guidance; code diffs land with repo targets).
        report.patch_advisories.push(PatchProposal {
            id: uuid::Uuid::new_v4(),
            finding_id: f.id,
            diff: String::new(),
            rationale: remediation(f),
        });
    }

    std::fs::write(
        artifacts_dir.join("blue_report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    Ok(report)
}
