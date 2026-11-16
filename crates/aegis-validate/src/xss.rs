//! XSS validator — inject a unique canary and require it reflected
//! unescaped in a script-executing context.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::verdict::Verdict;
use crate::validator::Validator;
use std::collections::HashMap;

pub struct XssValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for XssValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Xss
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let (Some(url), Some(param)) = (
            f.evidence["url"].as_str().map(|s| s.to_string()),
            f.evidence["param"].as_str().map(|s| s.to_string()),
        ) else {
            return Verdict::Rejected { reason: "evidence missing url/param".into() };
        };

        let marker = format!("aegxs{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let payload = format!("\"><svg/onload={}>", marker);
        let mut p = HashMap::new();
        p.insert(param.clone(), payload.clone());
        let resp = match self.probe.get(&url, &p).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };

        // Executing-context proof: the literal payload must come back
        // without HTML-escaping of the quote/angle brackets.
        if resp.body.contains(&payload) {
            return Verdict::Verified {
                reproduction: format!(
                    "GET {url}?{param}=<injected> -> reflected unescaped marker {marker} in HTML context"
                ),
            };
        }
        // Partial: marker reflected but context escaped.
        if resp.body.contains(&marker) {
            return Verdict::Rejected {
                reason: "marker reflected but output is escaped/sanitized".into(),
            };
        }
        Verdict::Rejected {
            reason: "payload not reflected".into(),
        }
    }
}
