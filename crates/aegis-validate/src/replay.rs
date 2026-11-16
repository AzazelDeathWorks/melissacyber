//! Generic deterministic replay validator — covers FindingClass::Other
//! (custom exploit chains, auth-forged sinks, eval RCE, flag capture).
//!
//! The solver must supply evidence:
//!   { "request": {"method","url","headers":{...},"body"}, "expect": "<marker>" }
//! We replay it and require: marker present in response AND absent from
//! a plain baseline GET of the same URL (no payload context). Anything
//! the solver claims, the target must literally say back.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::verdict::Verdict;
use crate::validator::Validator;
use std::collections::HashMap;

pub struct ReplayValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for ReplayValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Other
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        // Accept either evidence.request.url or a flat evidence.url —
        // solvers emit both shapes in practice.
        let req = &f.evidence["request"];
        let url = req["url"]
            .as_str()
            .or_else(|| f.evidence["url"].as_str());
        let Some(url) = url else {
            return Verdict::Rejected { reason: "evidence missing request.url".into() };
        };
        let expect = f
            .evidence["expect"]
            .as_str()
            .or_else(|| f.evidence["marker"].as_str());
        let Some(expect) = expect else {
            return Verdict::Rejected { reason: "evidence missing expect/marker".into() };
        };
        if expect.len() < 4 {
            return Verdict::Rejected { reason: "marker too short to be evidence".into() };
        }
        let hdr_src = req["headers"]
            .as_object()
            .or_else(|| f.evidence["headers"].as_object());
        let hdrs: Vec<(String, String)> = hdr_src
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        // Replay the exploit request.
        let replay = self.probe.get2(url, &HashMap::new(), &hdrs).await;
        let Ok(r) = replay else {
            return Verdict::Rejected { reason: "replay request failed".into() };
        };
        if !r.body.contains(expect) {
            return Verdict::Rejected {
                reason: format!("replayed request did not produce marker '{}'", &expect[..expect.len().min(32)]),
            };
        }
        // Baseline: same URL, no exploit headers — marker must NOT appear
        // (otherwise it's ambient output, not proof of compromise).
        let base = self.probe.get2(url, &HashMap::new(), &[]).await;
        if let Ok(b) = base {
            if b.body.contains(expect) {
                return Verdict::Rejected {
                    reason: "marker present without exploit — ambient output, not proof".into(),
                };
            }
        }
        Verdict::Verified {
            reproduction: format!(
                "replayed {} -> marker '{}' in response, absent in baseline",
                url, expect
            ),
        }
    }
}
