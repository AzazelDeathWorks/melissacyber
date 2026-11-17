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
        // Explicit marker first; otherwise mine candidates from the solver's
        // observed evidence (flag{...}, keyword-adjacent tokens) — rescue
        // real findings that only failed the schema.
        let mut candidates: Vec<String> = f
            .evidence["expect"]
            .as_str()
            .or_else(|| f.evidence["marker"].as_str())
            .map(|m| vec![m.to_string()])
            .unwrap_or_else(|| crate::validator::extract_markers(&f.evidence));
        candidates.retain(|c| c.len() >= 4);
        if candidates.is_empty() {
            return Verdict::Rejected { reason: "evidence missing expect/marker".into() };
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
        // Baseline once: same URL, plain GET, no exploit context.
        let base_body = self
            .probe
            .get2(url, &HashMap::new(), &[])
            .await
            .map(|b| b.body)
            .unwrap_or_default();
        let mut hits = vec![];
        for expect in &candidates {
            if r.body.contains(expect.as_str()) && !base_body.contains(expect.as_str()) {
                hits.push(expect.clone());
            }
        }
        let Some(expect) = hits.into_iter().next() else {
            return Verdict::Rejected {
                reason: format!(
                    "replayed request produced none of {} marker candidate(s)",
                    candidates.len()
                ),
            };
        };
        Verdict::Verified {
            reproduction: format!(
                "replayed {method} {url} -> marker '{expect}' in response, absent in baseline",
            ),
        }
    }
}
