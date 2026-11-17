use crate::finding::{Finding, FindingClass};
use crate::verdict::Verdict;
use std::collections::BTreeMap;
use std::sync::Arc;

/// One validator per finding class. Pure code: canary injection,
/// OOB callback correlation, replay diffing. WASM plugins can extend.
#[async_trait::async_trait]
pub trait Validator: Send + Sync {
    fn class(&self) -> FindingClass;
    async fn validate(&self, finding: &Finding) -> Verdict;
}

#[derive(Default)]
pub struct ValidatorRegistry {
    validators: BTreeMap<String, Arc<dyn Validator>>,
}

impl ValidatorRegistry {
    pub fn register(&mut self, v: Arc<dyn Validator>) {
        self.validators.insert(format!("{:?}", v.class()), v);
    }

    pub fn get(&self, class: &FindingClass) -> Option<Arc<dyn Validator>> {
        self.validators.get(&format!("{class:?}")).cloned()
    }
}

/// Pull headers the solver used in its exploit (e.g. forged auth) out of
/// `evidence["headers"]` (or `evidence["request"]["headers"]`) so
/// validators replay with the same context.
pub fn evidence_headers(f: &crate::finding::Finding) -> Vec<(String, String)> {
    let m = f.evidence["headers"]
        .as_object()
        .or_else(|| f.evidence["request"]["headers"].as_object());
    m.map(|m| {
        m.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    })
    .unwrap_or_default()
}

/// Injection-point aware send: reads `evidence` fields
///   url, param, in ("query"|"form"|"json"|"header"|"path"),
///   method (default GET), headers / request.headers
/// and replays `val` at the declared injection point. This is how the
/// whole HTTP surface (not just GET query params) becomes testable.
pub async fn send_value(
    probe: &crate::probe::ProbeClient,
    ev: &serde_json::Value,
    val: &str,
) -> anyhow::Result<crate::probe::ProbeResponse> {
    let url = ev["url"]
        .as_str()
        .or_else(|| ev["request"]["url"].as_str())
        .ok_or_else(|| anyhow::anyhow!("evidence missing url"))?
        .to_string();
    let param = ev["param"].as_str().unwrap_or("").to_string();
    let inj = ev["in"]
        .as_str()
        .or_else(|| ev["request"]["in"].as_str())
        .unwrap_or("query");
    let method = ev["method"]
        .as_str()
        .or_else(|| ev["request"]["method"].as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let mut hdrs: Vec<(String, String)> = ev["headers"]
        .as_object()
        .or_else(|| ev["request"]["headers"].as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut params = std::collections::HashMap::new();
    let mut body: Option<String> = None;
    match inj {
        "form" | "body" => {
            if method == "GET" {
                // form params on a GET still go in the query string
                params.insert(param.clone(), val.to_string());
            } else {
                body = Some(format!(
                    "{}={}",
                    urlencoding(&param),
                    urlencoding(val)
                ));
                if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                    hdrs.push(("content-type".into(), "application/x-www-form-urlencoded".into()));
                }
            }
        }
        "json" => {
            body = Some(serde_json::json!({ param.clone(): val }).to_string());
            if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                hdrs.push(("content-type".into(), "application/json".into()));
            }
        }
        "header" => {
            hdrs.push((param.clone(), val.to_string()));
        }
        "path" => {
            // `{param}` placeholder in the URL is replaced; otherwise the
            // value is appended as a trailing segment.
            let u = if url.contains('{') {
                let mut u2 = url.clone();
                for (k, v) in ev["path_params"]
                    .as_object()
                    .map(|m| m.clone())
                    .unwrap_or_default()
                {
                    if let Some(s) = v.as_str() {
                        u2 = u2.replace(&format!("{{{k}}}"), s);
                    }
                }
                u2.replace(&format!("{{{param}}}"), &percent_path(val))
            } else {
                format!("{}/{}", url.trim_end_matches('/'), percent_path(val))
            };
            return probe.send(&method, &u, &params, &hdrs, body).await;
        }
        _ => {
            params.insert(param.clone(), val.to_string());
        }
    }
    probe.send(&method, &url, &params, &hdrs, body).await
}

/// URL-encode for form bodies (application/x-www-form-urlencoded).
fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-encode for a URL path segment.
fn percent_path(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
