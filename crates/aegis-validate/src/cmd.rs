//! Command injection: arithmetic-eval + timing proofs.
//!
//! The canary is `echo $((691*689))` — the payload string never contains
//! the expected output `476099`, so a reflected-but-not-executed payload
//! cannot satisfy the check (no false-positive path).

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::{send_value, Validator};
use crate::verdict::Verdict;
use std::time::Duration;

pub struct CmdInjectionValidator {
    pub probe: ProbeClient,
}

const MARKER: &str = "476099"; // 691*689

#[async_trait::async_trait]
impl Validator for CmdInjectionValidator {
    fn class(&self) -> FindingClass {
        FindingClass::CmdInjection
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

        // 1. Arithmetic-eval: injected command output must appear in
        //    response. "476099" is never part of the payload text.
        for payload in [
            ";echo $((691*689))".to_string(),
            "|echo $((691*689))".to_string(),
            "$(echo $((691*689)))".to_string(),
            "`echo $((691*689))`".to_string(),
            "1;echo $((691*689))".to_string(),
            "&& echo $((691*689))".to_string(),
        ] {
            if let Ok(r) = send(&payload).await {
                if r.body.contains(MARKER) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "injected {payload} -> $((691*689)) evaluated to {MARKER} in response"
                        ),
                    };
                }
            }
        }

        // 2. Timing: sleep injection must actually delay (min of 2
        //    payload samples vs max of 2 baseline samples).
        let mut base_t = vec![];
        let mut inj_t = vec![];
        for _ in 0..2 {
            if let Ok(b) = send("1").await {
                base_t.push(b.elapsed);
            }
            if let Ok(r) = send("; sleep 3").await {
                inj_t.push(r.elapsed);
            }
        }
        if base_t.len() == 2 && inj_t.len() == 2 {
            base_t.sort();
            inj_t.sort();
            if inj_t[0] > base_t[1] + Duration::from_millis(1500) {
                return Verdict::Verified {
                    reproduction: format!(
                        "injected '; sleep 3' -> {}ms vs {}ms baseline",
                        inj_t[0].as_millis(),
                        base_t[1].as_millis()
                    ),
                };
            }
        }
        Verdict::Rejected { reason: "no command-evaluation or timing delay".into() }
    }
}
