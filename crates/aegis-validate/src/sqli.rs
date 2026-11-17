//! SQLi validator — boolean differential + error signatures + timing.
//! Deterministic reproduction; an agent's claim alone proves nothing.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::{send_value, Validator};
use crate::verdict::Verdict;

const ERROR_SIGS: &[&str] = &[
    "sql syntax", "mysql_fetch", "ORA-0", "PostgreSQL", "psql: error",
    "SQLite3::", "sqlite error", "ODBC", "SQLSTATE", "syntax error at or near",
    "unclosed quotation mark", "quoted string not properly terminated",
    "Microsoft OLE DB Provider for SQL", "You have an error in your SQL",
];

pub struct SqliValidator {
    pub probe: ProbeClient,
}

/// Content similarity robust to minified JSON (whitespace jaccard fails
/// there): character 3-gram Dice coefficient.
fn sim3(a: &str, b: &str) -> f64 {
    fn grams(s: &str) -> std::collections::HashSet<u32> {
        let bs = s.as_bytes();
        if bs.len() < 3 {
            return std::iter::once(0u32).collect();
        }
        bs.windows(3)
            .map(|w| (w[0] as u32) << 16 | (w[1] as u32) << 8 | w[2] as u32)
            .collect()
    }
    let (ga, gb) = (grams(a), grams(b));
    let inter = ga.intersection(&gb).count() as f64;
    if ga.is_empty() && gb.is_empty() {
        return 1.0;
    }
    2.0 * inter / (ga.len() + gb.len()) as f64
}

impl SqliValidator {
    fn evidence_url(f: &Finding) -> Option<(String, String)> {
        let url = f.evidence["url"]
            .as_str()
            .or_else(|| f.evidence["request"]["url"].as_str())?
            .to_string();
        let param = f.evidence["param"].as_str().unwrap_or("").to_string();
        Some((url, param))
    }
}

#[async_trait::async_trait]
impl Validator for SqliValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Sqli
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let Some((url, param)) = Self::evidence_url(f) else {
            return Verdict::Rejected { reason: "evidence missing url/param".into() };
        };
        let send = |val: &str| {
            let probe = self.probe.clone();
            let ev = f.evidence.clone();
            let v = val.to_string();
            async move { send_value(&probe, &ev, &v).await }
        };

        let baseline = match send("1").await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("baseline failed: {e}") },
        };

        // 1. Error-based: quote injection must produce a DB error string.
        if let Ok(r) = send("1'").await {
            let low = r.body.to_lowercase();
            if let Some(sig) = ERROR_SIGS.iter().find(|s| low.contains(&s.to_lowercase())) {
                return Verdict::Verified {
                    reproduction: format!(
                        "{url} param={param}: injected ' -> status {}, DB error signature '{sig}'",
                        r.status
                    ),
                };
            }
        }

        // 2. Boolean differential: OR-true vs AND-false must diverge like
        //    baseline-vs-false, and both must differ from each other.
        let t = send("1' OR '1'='1").await;
        let f2 = send("1' AND '1'='2").await;
        if let (Ok(t), Ok(f2)) = (t, f2) {
            let true_like_base = sim3(&baseline.body, &t.body) > 0.9;
            let differs = sim3(&t.body, &f2.body) < 0.8;
            let false_differs_base = sim3(&baseline.body, &f2.body) < 0.9;
            if true_like_base && differs && false_differs_base {
                return Verdict::Verified {
                    reproduction: format!(
                        "{url} param={param}: 'OR'1'='1 ≈ baseline (sim {:.2}) but 'AND'1'='2 diverges (sim {:.2})",
                        sim3(&baseline.body, &t.body),
                        sim3(&t.body, &f2.body),
                    ),
                };
            }
        }

        // 3. Time-based: payload sleeps — server must actually delay.
        //    Median of 2 samples each side to resist jitter.
        let mut b0 = vec![];
        let mut b3 = vec![];
        for _ in 0..2 {
            if let Ok(r) = send("1' OR SLEEP(0)-- -").await {
                b0.push(r.elapsed);
            }
            if let Ok(r) = send("1' OR SLEEP(3)-- -").await {
                b3.push(r.elapsed);
            }
        }
        if b0.len() == 2 && b3.len() == 2 {
            b0.sort();
            b3.sort();
            if b3[0] > b0[1] + std::time::Duration::from_millis(2500) {
                return Verdict::Verified {
                    reproduction: format!(
                        "{url} param={param}: SLEEP(3) min {}ms vs SLEEP(0) max {}ms",
                        b3[0].as_millis(),
                        b0[1].as_millis()
                    ),
                };
            }
        }

        // 4. Auth-bypass tautology: classic login bypass — an invalid
        //    credential MUST fail while the tautology MUST flip to
        //    authenticated output (status or success markers).
        let neg = send(&format!("aegis_invalid_{}", &uuid::Uuid::new_v4().simple().to_string()[..8])).await;
        let inj = send("' OR '1'='1'-- ").await;
        if let (Ok(neg), Ok(inj)) = (neg, inj) {
            const SUCCESS: [&str; 6] = ["welcome", "flag{", "dashboard", "logout", "admin", "token"];
            let neg_low = neg.body.to_lowercase();
            let inj_low = inj.body.to_lowercase();
            let status_flip = neg.status >= 400 && (200..300).contains(&inj.status);
            let marker_hit = SUCCESS
                .iter()
                .any(|s| inj_low.contains(s) && !neg_low.contains(s));
            if (status_flip || marker_hit) && sim3(&neg.body, &inj.body) < 0.9 {
                return Verdict::Verified {
                    reproduction: format!(
                        "{url} param={param}: invalid creds -> {}, ' OR '1'='1'-- -> {} (auth bypass, body diverges sim {:.2})",
                        neg.status, inj.status, sim3(&neg.body, &inj.body)
                    ),
                };
            }
        }

        Verdict::Rejected {
            reason: "no error signature, boolean differential, time delay, or auth-bypass reproduced".into(),
        }
    }
}
