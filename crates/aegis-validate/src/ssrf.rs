//! SSRF validator — force the target to call our OOB listener and
//! correlate the unique token. Blind or not, the server-side fetch is
//! the only proof that counts.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::verdict::Verdict;
use crate::validator::Validator;
use aegis_sandbox::OobStore;
use std::collections::HashMap;
use std::time::Duration;

pub struct SsrfValidator {
    pub probe: ProbeClient,
    pub oob: OobStore,
    pub oob_base: String,
}

#[async_trait::async_trait]
impl Validator for SsrfValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Ssrf
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let (Some(url), Some(param)) = (
            f.evidence["url"].as_str().map(|s| s.to_string()),
            f.evidence["param"].as_str().map(|s| s.to_string()),
        ) else {
            return Verdict::Rejected { reason: "evidence missing url/param".into() };
        };

        let token = format!("ssrf{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let cb = format!("{}/{}/cb", self.oob_base, token);
        let mut p = HashMap::new();
        p.insert(param.clone(), cb.clone());
        if let Err(e) = self.probe.get(&url, &p).await {
            return Verdict::Rejected { reason: format!("trigger failed: {e}") };
        }

        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let hits = self.oob.hits_for(&token);
            if !hits.is_empty() {
                return Verdict::Verified {
                    reproduction: format!(
                        "GET {url}?{param}={cb} -> OOB hit from {} ({} hits)",
                        hits[0].remote,
                        hits.len()
                    ),
                };
            }
        }
        Verdict::Rejected {
            reason: "no OOB interaction observed within 5s".into(),
        }
    }
}
