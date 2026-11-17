//! Generic deterministic replay validator — covers FindingClass::Other
//! (custom exploit chains, auth-forged sinks, eval RCE, flag capture).
//!
//! Evidence shape:
//!   { "request": {"method","url","headers":{...},"body"},
//!     "expect": "<marker>" }
//! We replay it (any method/body) and require: marker present AND absent
//! from a baseline GET without exploit context.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::Validator;
use crate::verdict::Verdict;
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
        let method = req["method"].as_str().unwrap_or("GET");
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
        let body = req["body"]
            .as_str()
            .or_else(|| f.evidence["body"].as_str())
            .map(String::from);
        let params: HashMap<String, String> = req["params"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let replay = self.probe.send(method, url, &params, &hdrs, body).await;
        let Ok(r) = replay else {
            return Verdict::Rejected { reason: "replay request failed".into() };
        };
        if !r.body.contains(expect) {
            return Verdict::Rejected {
                reason: format!("replayed request did not produce marker '{}'", &expect[..expect.len().min(32)]),
            };
        }
        // Baseline: same URL, plain GET, no exploit context — marker must
        // NOT appear (otherwise it's ambient output, not proof).
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
                "replayed {method} {url} -> marker '{expect}' in response, absent in baseline",
            ),
        }
    }
}
