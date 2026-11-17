//! XSS validator — inject a unique canary and require it reflected
//! unescaped in a script-executing context.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::{send_value, Validator};
use crate::verdict::Verdict;

pub struct XssValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for XssValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Xss
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let has_url = f.evidence["url"].as_str().is_some()
            || f.evidence["request"]["url"].as_str().is_some();
        if !has_url {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        }

        let marker = format!("aegxs{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let payload = format!("\"><svg/onload={}>", marker);
        let resp = match send_value(&self.probe, &f.evidence, &payload).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };

        // Executing-context proof: the literal payload must come back
        // without HTML-escaping of the quote/angle brackets.
        if resp.body.contains(&payload) {
            return Verdict::Verified {
                reproduction: format!(
                    "injected {payload} -> reflected unescaped marker {marker} in HTML context"
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
