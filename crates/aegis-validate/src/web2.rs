//! Second wave of deterministic validators — class-specific, no AI.

use crate::finding::{Finding, FindingClass, Severity};
use crate::probe::ProbeClient;
use crate::validator::{evidence_headers, send_value, Validator};
use crate::verdict::Verdict;


fn ev_str<'a>(f: &'a Finding, keys: &[&'a str]) -> &'a str {
    for k in keys {
        if let Some(v) = f.evidence[*k].as_str() {
            return v;
        }
        if let Some(v) = f.evidence["request"][*k].as_str() {
            return v;
        }
    }
    ""
}

// ---------- open redirect ----------

pub struct OpenRedirectValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for OpenRedirectValidator {
    fn class(&self) -> FindingClass {
        FindingClass::OpenRedirect
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let marker = "aegis-oob-redirect.example";
        let val = format!("https://{marker}/x");
        let r = match send_value(&self.probe, &f.evidence, &val).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };
        let loc = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if loc.contains(marker) {
            Verdict::Verified {
                reproduction: format!(
                    "open redirect verified: injected '{val}' -> Location: {loc}"
                ),
            }
        } else {
            Verdict::Rejected {
                reason: format!("no redirect to injected host (Location: {loc:?})"),
            }
        }
    }
}

// ---------- host header injection ----------

pub struct HostHeaderValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for HostHeaderValidator {
    fn class(&self) -> FindingClass {
        FindingClass::HostHeader
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let url = ev_str(f, &["url"]).to_string();
        let marker = "aegis-hh-evil.example";
        let mut hdrs = evidence_headers(f);
        hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        hdrs.push(("Host".into(), marker.into()));
        let method = ev_str(f, &["method"]);
        let method = if method.is_empty() { "GET" } else { method };
        let r = self
            .probe
            .send(method, &url, &Default::default(), &hdrs, None)
            .await;
        let r = match r {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };
        let reflected = r.body.contains(marker)
            || r.headers.iter().any(|(_, v)| v.contains(marker));
        if reflected {
            Verdict::Verified {
                reproduction: format!(
                    "host-header injection verified: Host: {marker} reflected in response (status {})",
                    r.status
                ),
            }
        } else {
            Verdict::Rejected {
                reason: "injected Host not reflected".into(),
            }
        }
    }
}

// ---------- secrets in response ----------

const SECRET_RE_SUGGESTIVE: &[&str] = &[
    "-----BEGIN", "AKIA", "ghp_", "xoxb-", "sk_live_", "AIza",
    "private_key", "password\":", "api_key\":",
];

pub struct SecretsValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for SecretsValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Secrets
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let expect = ev_str(f, &["expect", "marker"]).to_string();
        let needle = if expect.len() >= 4 {
            expect
        } else {
            // replay claimed response marker via the evidence request
            ev_str(f, &["payload"]).to_string()
        };
        let r = match send_value(&self.probe, &f.evidence, &ev_str(f, &["payload"]).to_string()).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };
        let hit = if needle.len() >= 4 && r.body.contains(&needle) {
            Some(format!("expected marker '{needle}'"))
        } else {
            SECRET_RE_SUGGESTIVE
                .iter()
                .find(|s| r.body.contains(**s))
                .map(|s| format!("secret signature '{s}'"))
        };
        match hit {
            Some(h) => Verdict::Verified {
                reproduction: format!("secret exposure verified ({h}) in response from {}", ev_str(f, &["url"])),
            },
            None => Verdict::Rejected {
                reason: "no secret signature or claimed marker in replayed response".into(),
            },
        }
    }
}

// ---------- CSRF (state-changing endpoint lacking a token) ----------

pub struct CsrfValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for CsrfValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Csrf
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        // Deterministic check: the claimed state-changing request succeeds
        // with no CSRF token and a foreign Origin — that IS the vuln.
        let url = ev_str(f, &["url"]).to_string();
        let method = ev_str(f, &["method"]);
        let method = if method.is_empty() { "POST" } else { method }.to_string();
        let mut hdrs = evidence_headers(f);
        hdrs.retain(|(k, _)| {
            !k.to_ascii_lowercase().contains("csrf")
                && !k.to_ascii_lowercase().contains("xsrf")
                && !k.eq_ignore_ascii_case("origin")
                && !k.eq_ignore_ascii_case("referer")
        });
        hdrs.push(("Origin".into(), "https://evil.example".into()));
        let body = ev_str(f, &["body"]);
        let r = self
            .probe
            .send(&method, &url, &Default::default(), &hdrs, if body.is_empty() { None } else { Some(body.to_string()) })
            .await;
        match r {
            Ok(r) if (200..400).contains(&r.status) => Verdict::Verified {
                reproduction: format!(
                    "csrf verified: {method} {url} accepted (status {}) with foreign Origin and no token",
                    r.status
                ),
            },
            Ok(r) => Verdict::Rejected {
                reason: format!("request rejected by server (status {}) — token likely enforced", r.status),
            },
            Err(e) => Verdict::Rejected { reason: format!("probe failed: {e}") },
        }
    }
}

// ---------- IDOR ----------

pub struct IdorValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for IdorValidator {
    fn class(&self) -> FindingClass {
        FindingClass::AuthzIdor
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        // Evidence-driven: solver supplies `param` + a neighboring id
        // `alt_id`; verified when the alt object returns 200 with content
        // different from an error/empty page.
        let alt = ev_str(f, &["alt_id", "payload"]).to_string();
        if alt.is_empty() {
            return Verdict::Rejected { reason: "evidence lacks alt_id".into() };
        }
        let r = match send_value(&self.probe, &f.evidence, &alt).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };
        if r.status == 200 && r.body.len() > 64 {
            Verdict::Verified {
                reproduction: format!(
                    "idor verified: object '{alt}' at {} returned status 200 ({} bytes) — object reference accepted without authz check",
                    ev_str(f, &["url"]),
                    r.body.len()
                ),
            }
        } else {
            Verdict::Rejected {
                reason: format!("alt object fetch failed (status {})", r.status),
            }
        }
    }
}

// ---------- file upload ----------

pub struct FileUploadValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for FileUploadValidator {
    fn class(&self) -> FindingClass {
        FindingClass::FileUpload
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        // Solver claims an uploaded file is retrievable/executable:
        // evidence {url: <fetch url>, expect: <marker placed in file>}.
        let expect = ev_str(f, &["expect", "marker"]).to_string();
        let url = ev_str(f, &["url"]).to_string();
        if expect.len() < 4 || url.is_empty() {
            return Verdict::Rejected { reason: "evidence lacks fetch url/marker".into() };
        }
        let hdrs = evidence_headers(f);
        match self.probe.get2(&url, &Default::default(), &hdrs).await {
            Ok(r) if r.status == 200 && r.body.contains(&expect) => Verdict::Verified {
                reproduction: format!(
                    "file-upload verified: uploaded marker '{expect}' retrievable at {url} (status {})",
                    r.status
                ),
            },
            Ok(r) => Verdict::Rejected {
                reason: format!("uploaded content not retrievable (status {})", r.status),
            },
            Err(e) => Verdict::Rejected { reason: format!("probe failed: {e}") },
        }
    }
}

// ---------- deserialization ----------

const DESER_SIGS: &[&str] = &[
    "java.io.ObjectInputStream",
    "unserialize(",
    "pickle.loads",
    "Marshal.load",
    "readObject",
    "InvocationTargetException",
    "O:8:", "rO0",
];

pub struct DeserValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for DeserValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Deserialization
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        // Error-signature confirmation: replay the claimed gadget/probe
        // payload; a deserialization engine's own error confirms the sink.
        let payload = ev_str(f, &["payload"]).to_string();
        if payload.is_empty() {
            return Verdict::Rejected { reason: "evidence lacks payload".into() };
        }
        let r = match send_value(&self.probe, &f.evidence, &payload).await {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };
        if let Some(sig) = DESER_SIGS.iter().find(|s| r.body.contains(**s)) {
            return Verdict::Verified {
                reproduction: format!(
                    "deserialization sink confirmed: payload triggered engine signature '{sig}' (status {})",
                    r.status
                ),
            };
        }
        // timing alternative
        if f.evidence["delay_ms"].as_u64().is_some_and(|d| d > 2000)
            && r.elapsed.as_secs() >= 2
        {
            return Verdict::Verified {
                reproduction: format!(
                    "deserialization timing confirmed: replay elapsed {:?}",
                    r.elapsed
                ),
            };
        }
        Verdict::Rejected {
            reason: "no deserialization signature or timing".into(),
        }
    }
}

// ---------- race condition ----------

pub struct RaceValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for RaceValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Race
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        // Replay the same request N times in parallel; verified when MORE
        // than the claimed-allowed count succeed (e.g. coupon/transfer used twice).
        let n: usize = 8;
        let method = ev_str(f, &["method"]);
        let method = if method.is_empty() { "POST" } else { method }.to_string();
        let url = ev_str(f, &["url"]).to_string();
        let hdrs = evidence_headers(f);
        let body = ev_str(f, &["body"]);
        let expect = ev_str(f, &["expect", "marker"]).to_string();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..n {
            let (p, m, u, h, b) = (
                self.probe.clone(),
                method.clone(),
                url.clone(),
                hdrs.clone(),
                body.to_string(),
            );
            set.spawn(async move {
                p.send(&m, &u, &Default::default(), &h, if b.is_empty() { None } else { Some(b.clone()) }).await
            });
        }
        let mut hits = 0usize;
        while let Some(res) = set.join_next().await {
            if let Ok(Ok(r)) = res {
                let ok = if expect.len() >= 4 {
                    r.status < 400 && r.body.contains(&expect)
                } else {
                    (200..300).contains(&r.status)
                };
                if ok {
                    hits += 1;
                }
            }
        }
        let claimed_limit = f.evidence["allowed_count"].as_u64().unwrap_or(1) as usize;
        if hits > claimed_limit {
            Verdict::Verified {
                reproduction: format!(
                    "race condition verified: {hits}/{n} parallel requests succeeded (allowed: {claimed_limit})"
                ),
            }
        } else {
            Verdict::Rejected {
                reason: format!("only {hits}/{n} parallel requests succeeded"),
            }
        }
    }
}

// ---------- business logic invariant ----------

pub struct BusinessLogicValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for BusinessLogicValidator {
    fn class(&self) -> FindingClass {
        FindingClass::BusinessLogic
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        // Invariant check via expect marker (e.g. negative quantity accepted).
        let expect = ev_str(f, &["expect"]).to_string();
        let payload = ev_str(f, &["payload"]).to_string();
        if expect.len() < 4 || payload.is_empty() {
            return Verdict::Rejected { reason: "evidence lacks payload/expect".into() };
        }
        match send_value(&self.probe, &f.evidence, &payload).await {
            Ok(r) if r.body.contains(&expect) => Verdict::Verified {
                reproduction: format!(
                    "business-logic invariant violated: '{expect}' observed after '{payload}'"
                ),
            },
            Ok(_) => Verdict::Rejected {
                reason: "invariant marker absent after replay".into(),
            },
            Err(e) => Verdict::Rejected { reason: format!("probe failed: {e}") },
        }
    }
}
