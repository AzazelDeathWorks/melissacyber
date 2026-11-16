//! SSTI: arithmetic-evaluation proof — 7*7 must render as 49.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::Validator;
use crate::verdict::Verdict;
use std::collections::HashMap;

pub struct SstiValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for SstiValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Ssti
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let hdrs = crate::validator::evidence_headers(f);
        let (Some(url), Some(param)) = (
            f.evidence["url"].as_str().map(|s| s.to_string()),
            f.evidence["param"].as_str().map(|s| s.to_string()),
        ) else {
            return Verdict::Rejected { reason: "evidence missing url/param".into() };
        };
        let send = |val: String| {
            let mut p = HashMap::new();
            p.insert(param.clone(), val);
            let (u, pp) = (url.clone(), p);
            let probe = self.probe.clone();
            let h2 = hdrs.clone(); async move { probe.get2(&u, &pp, &h2).await }
        };

        // Baseline must not contain the evaluated marker by chance.
        let Ok(base) = send("aegisbase".into()).await else {
            return Verdict::Rejected { reason: "baseline probe failed".into() };
        };
        let marker = "475906"; // 691*689 — an improbable literal
        for payload in [
            format!("{{{{691*689}}}}"),
            "${{691*689}}".to_string(),
            format!("#{{691*689}}"),
            format!("<%= 691*689 %>"),
            format!("*{{691*689}}*"),
        ] {
            if let Ok(r) = send(payload.clone()).await {
                if r.body.contains(marker) && !base.body.contains(marker) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "GET {url}?{param}={payload} -> server evaluated 691*689={marker} (template engine execution)"
                        ),
                    };
                }
            }
        }
        Verdict::Rejected { reason: "no template evaluation observed".into() }
    }
}
