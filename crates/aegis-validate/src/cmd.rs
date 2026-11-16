//! Command injection: canary-echo + timing proofs.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::Validator;
use crate::verdict::Verdict;
use std::collections::HashMap;
use std::time::Duration;

pub struct CmdInjectionValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for CmdInjectionValidator {
    fn class(&self) -> FindingClass {
        FindingClass::CmdInjection
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

        // 1. Canary echo: injected command output must appear in response.
        let marker = format!("aegcmd{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        for payload in [
            format!(";echo {marker}"),
            format!("| echo {marker}"),
            format!("$(echo {marker})"),
            format!("`echo {marker}`"),
            format!("1;echo {marker}"),
        ] {
            if let Ok(r) = send(payload.clone()).await {
                if r.body.contains(&marker) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "GET {url}?{param}={payload} -> canary {marker} echoed in response"
                        ),
                    };
                }
            }
        }

        // 2. Timing: sleep injection must actually delay the response.
        let base = send("1".into()).await;
        if let Ok(b) = base {
            for payload in ["; sleep 3", "| sleep 3", "&& sleep 3"] {
                if let Ok(r) = send(payload.to_string()).await {
                    if r.elapsed > b.elapsed + Duration::from_millis(2500) {
                        return Verdict::Verified {
                            reproduction: format!(
                                "GET {url}?{param}={payload} -> {ms}ms vs {base_ms}ms baseline",
                                ms = r.elapsed.as_millis(),
                                base_ms = b.elapsed.as_millis()
                            ),
                        };
                    }
                }
            }
        }
        Verdict::Rejected { reason: "no canary echo or timing delay".into() }
    }
}
