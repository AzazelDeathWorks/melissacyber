//! SSRF validator — force the target to call our OOB listener and
//! correlate the unique token. Blind or not, the server-side fetch is
//! the only proof that counts.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::{send_value, Validator};
use crate::verdict::Verdict;
use aegis_sandbox::OobStore;
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
        let has_url = f.evidence["url"].as_str().is_some()
            || f.evidence["request"]["url"].as_str().is_some();
        if !has_url {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        };

        let token = format!("ssrf{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let cb = format!("{}/{}/cb", self.oob_base, token);
        // If evidence declares a param, inject there; if the evidence URL
        // itself is the fetch-target, replay the whole request shape.
        let mut ev = f.evidence.clone();
        let res = if ev["param"].as_str().is_some() {
            send_value(&self.probe, &ev, &cb).await
        } else {
            ev["url"] = serde_json::json!(cb);
            send_value(&self.probe, &ev, "1").await
        };
        if let Err(e) = res {
            return Verdict::Rejected { reason: format!("trigger failed: {e}") };
        }

        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let hits = self.oob.hits_for(&token);
            if !hits.is_empty() {
                return Verdict::Verified {
                    reproduction: format!(
                        "OOB callback {cb} hit from {} ({} hits)",
                        hits[0].remote,
                        hits.len()
                    ),
                };
            }
        }
        Verdict::Rejected {
            reason: "no OOB interaction observed within 10s".into(),
        }
    }
}
