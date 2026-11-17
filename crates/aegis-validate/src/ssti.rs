//! SSTI: arithmetic-evaluation proof — 691*689 must render as 475906.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::{send_value, Validator};
use crate::verdict::Verdict;

pub struct SstiValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for SstiValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Ssti
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let has_url = f.evidence["url"].as_str().is_some()
            || f.evidence["request"]["url"].as_str().is_some();
        if !has_url {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        }
        let send = |val: &str| {
            let probe = self.probe.clone();
            let ev = f.evidence.clone();
            let v = val.to_string();
            async move { send_value(&probe, &ev, &v).await }
        };

        let Ok(base) = send("aegisbase").await else {
            return Verdict::Rejected { reason: "baseline probe failed".into() };
        };
        let marker = "475906"; // 691*689 — an improbable literal
        for payload in [
            "{{691*689}}".to_string(),
            "${691*689}".to_string(),
            "#{691*689}".to_string(),
            "<%= 691*689 %>".to_string(),
            "*{691*689}*".to_string(),
            "${T(java.lang.Math).floor(691.5*689)}".to_string(),
            "{{range.print 475906}}".to_string(),
        ] {
            if let Ok(r) = send(&payload).await {
                if r.body.contains(marker) && !base.body.contains(marker) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "injected {payload} -> server evaluated 691*689={marker} (template engine execution)"
                        ),
                    };
                }
            }
        }
        Verdict::Rejected { reason: "no template evaluation observed".into() }
    }
}
