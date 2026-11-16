//! SQLi validator — boolean differential + error signatures + timing.
//! Deterministic reproduction; an agent's claim alone proves nothing.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::verdict::Verdict;
use crate::validator::Validator;
use std::collections::HashMap;

const ERROR_SIGS: &[&str] = &[
    "sql syntax", "mysql_fetch", "ORA-0", "PostgreSQL", "psql: error",
    "SQLite3::", "sqlite error", "ODBC", "SQLSTATE", "syntax error at or near",
    "unclosed quotation mark", "quoted string not properly terminated",
    "Microsoft OLE DB Provider for SQL", "You have an error in your SQL",
];

pub struct SqliValidator {
    pub probe: ProbeClient,
}

fn jaccard(a: &str, b: &str) -> f64 {
    let wa: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let wb: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if wa.is_empty() && wb.is_empty() {
        return 1.0;
    }
    let inter = wa.intersection(&wb).count() as f64;
    inter / (wa.union(&wb).count() as f64)
}

impl SqliValidator {
    fn evidence_url(f: &Finding) -> Option<(String, String)> {
        let url = f.evidence["url"].as_str()?.to_string();
        let param = f.evidence["param"].as_str()?.to_string();
        Some((url, param))
    }
}

#[async_trait::async_trait]
impl Validator for SqliValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Sqli
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let hdrs = crate::validator::evidence_headers(f);
        let Some((url, param)) = Self::evidence_url(f) else {
            return Verdict::Rejected { reason: "evidence missing url/param".into() };
        };
        let send = |val: String| {
            let mut p = HashMap::new();
            p.insert(param.clone(), val);
            let (u, pp) = (url.clone(), p);
            let probe = self.probe.clone();
            let h2 = hdrs.clone(); async move { probe.get2(&u, &pp, &h2).await }
        };

        let baseline = match send("1".into()).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("baseline failed: {e}") },
        };

        // 1. Error-based: quote injection must produce a DB error string.
        let quoted = send("1'".into()).await;
        if let Ok(r) = &quoted {
            let low = r.body.to_lowercase();
            if let Some(sig) = ERROR_SIGS.iter().find(|s| low.contains(&s.to_lowercase())) {
                return Verdict::Verified {
                    reproduction: format!(
                        "GET {url}?{param}=1' -> status {}, DB error signature '{sig}'",
                        r.status
                    ),
                };
            }
        }

        // 2. Boolean differential: OR-true vs AND-false must diverge like
        //    baseline-vs-false, and both must differ from each other.
        let t = send("1' OR '1'='1".into()).await;
        let f2 = send("1' AND '1'='2".into()).await;
        if let (Ok(t), Ok(f2)) = (t, f2) {
            let true_like_base = jaccard(&baseline.body, &t.body) > 0.9;
            let differs = jaccard(&t.body, &f2.body) < 0.8;
            let false_differs_base = jaccard(&baseline.body, &f2.body) < 0.9;
            if true_like_base && differs && false_differs_base {
                return Verdict::Verified {
                    reproduction: format!(
                        "GET {url}?{param} : 'OR'1'='1 ≈ baseline (sim {:.2}) but 'AND'1'='2 diverges (sim {:.2})",
                        jaccard(&baseline.body, &t.body),
                        jaccard(&t.body, &f2.body),
                    ),
                };
            }
        }

        // 3. Time-based: payload sleeps — server must actually delay.
        let t0 = send("1' OR SLEEP(0)-- -".into()).await;
        if let Ok(r0) = t0 {
            let slow = send("1' OR SLEEP(3)-- -".into()).await;
            if let Ok(rs) = slow {
                if rs.elapsed > r0.elapsed + std::time::Duration::from_millis(2500) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "GET {url}?{param}: SLEEP(3) delayed {}ms vs {}ms baseline",
                            rs.elapsed.as_millis(),
                            r0.elapsed.as_millis()
                        ),
                    };
                }
            }
        }

        // 4. Auth-bypass tautology: classic login bypass — an invalid
        //    credential MUST fail while the tautology MUST flip to
        //    authenticated output (status or success markers).
        let neg = send(format!("aegis_invalid_{}", &uuid::Uuid::new_v4().simple().to_string()[..8])).await;
        let inj = send("' OR '1'='1'-- ".into()).await;
        if let (Ok(neg), Ok(inj)) = (neg, inj) {
            const SUCCESS: [&str; 6] = ["welcome", "flag{", "dashboard", "logout", "admin", "token"];
            let neg_low = neg.body.to_lowercase();
            let inj_low = inj.body.to_lowercase();
            let status_flip = neg.status >= 400 && (200..300).contains(&inj.status);
            let marker_hit = SUCCESS
                .iter()
                .any(|s| inj_low.contains(s) && !neg_low.contains(s));
            if (status_flip || marker_hit) && jaccard(&neg.body, &inj.body) < 0.9 {
                return Verdict::Verified {
                    reproduction: format!(
                        "GET {url}?{param}: invalid creds -> {}, ' OR '1'='1'-- -> {} (auth bypass, body diverges sim {:.2})",
                        neg.status, inj.status, jaccard(&neg.body, &inj.body)
                    ),
                };
            }
        }

        Verdict::Rejected {
            reason: "no error signature, boolean differential, time delay, or auth-bypass reproduced".into(),
        }
    }
}
