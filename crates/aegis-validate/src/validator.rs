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
    let param = sanitize_param(ev["param"].as_str().unwrap_or(""));
    let inj = ev["in"]
        .as_str()
        .or_else(|| ev["request"]["in"].as_str())
        .unwrap_or("query");
    let method = ev["method"]
        .as_str()
        .or_else(|| ev["request"]["method"].as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let mut hdrs: Vec<(String, String)> = collect_headers(ev);

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
            // Merge the injected value into the evidence's original JSON
            // body so sibling fields (e.g. password on a login POST) are
            // preserved; fall back to a single-field body when the
            // evidence body is absent or not JSON.
            let mut obj = ev["body"]
                .as_str()
                .or_else(|| ev["request"]["body"].as_str())
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            obj.insert(param.clone(), serde_json::Value::String(val.to_string()));
            body = Some(serde_json::Value::Object(obj).to_string());
            if !hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                hdrs.push(("content-type".into(), "application/json".into()));
            }
        }
        "header" => {
            hdrs.push((param.clone(), val.to_string()));
        }
        "path" => {
            // `{param}` placeholder in the URL is replaced. Otherwise
            // REST object addressing: the object reference IS the last
            // path segment — replace it (appending a trailing segment
            // addresses a nonexistent child resource and both probe and
            // baseline hit the same object, killing real IDORs).
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
            } else if let Some(orig) = ev["value"].as_str().or_else(|| ev["original"].as_str()).filter(|s| !s.is_empty()) {
                // solver told us the exact object id it saw — swap it
                url.replacen(orig, &percent_path(val), 1)
            } else {
                let base = url.split('?').next().unwrap_or(&url);
                match base.rfind('/') {
                    Some(idx) => format!("{}/{}", &base[..idx], percent_path(val)),
                    None => format!("{}/{}", base.trim_end_matches('/'), percent_path(val)),
                }
            };
            return probe.send(&method, &u, &params, &hdrs, body).await;
        }
        _ => {
            params.insert(param.clone(), val.to_string());
        }
    }
    // rebuild URL: drop solver-supplied payload query for the target param
    // and sanitize anything left, so reqwest never sees raw spaces/quotes.
    let clean_url = rebuild_url(&url, &param);
    probe.send(&method, &clean_url, &params, &hdrs, body).await
}

/// Same injection-point-aware send as `send_value`, but does NOT follow
/// redirects — the 3xx response and its Location header are returned
/// verbatim. Open-redirect validation needs the raw hop (following the
/// redirect would hit the scope check on the out-of-scope target).
pub async fn send_value_nofollow(
    probe: &crate::probe::ProbeClient,
    ev: &serde_json::Value,
    val: &str,
) -> anyhow::Result<crate::probe::ProbeResponse> {
    let url = ev["url"]
        .as_str()
        .or_else(|| ev["request"]["url"].as_str())
        .ok_or_else(|| anyhow::anyhow!("evidence missing url"))?
        .to_string();
    let param = sanitize_param(ev["param"].as_str().unwrap_or(""));
    let method = ev["method"]
        .as_str()
        .or_else(|| ev["request"]["method"].as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let mut hdrs: Vec<(String, String)> = collect_headers(ev);
    let mut params = std::collections::HashMap::new();
    let mut body: Option<String> = None;
    match ev["in"]
        .as_str()
        .or_else(|| ev["request"]["in"].as_str())
        .unwrap_or("query")
    {
        "form" | "body" if method != "GET" => {
            body = Some(format!("{}={}", urlencoding(&param), urlencoding(val)));
        }
        "json" => {
            let mut obj = ev["body"]
                .as_str()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            obj.insert(param.clone(), serde_json::Value::String(val.to_string()));
            body = Some(serde_json::Value::Object(obj).to_string());
        }
        "header" => {
            hdrs.push((param.clone(), val.to_string()));
        }
        _ => {
            params.insert(param.clone(), val.to_string());
        }
    }
    let clean_url = rebuild_url(&url, &param);
    probe
        .send_nofollow(&method, &clean_url, &params, &hdrs, body)
        .await
}

/// URL-encode for form bodies (application/x-www-form-urlencoded).
pub fn urlencoding(s: &str) -> String {
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

/// Solver-written param names get polluted with annotations ("u (query)").
/// Keep only real param-name chars.
pub fn sanitize_param(p: &str) -> String {
    p.chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '[' | ']' | '.'))
        .collect()
}

/// Merge params into a URL that may already carry a query (possibly with
/// the exploit payload in it): keep base + existing non-target pairs and
/// percent-encode everything, so reqwest never sees a raw space/quote.
pub fn rebuild_url(raw: &str, drop_param: &str) -> String {
    let (base, query) = match raw.split_once('?') {
        Some((b, q)) => (b, q),
        None => (raw, ""),
    };
    let kept: Vec<String> = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter(|kv| {
            let name = kv.split('=').next().unwrap_or("");
            name != drop_param
        })
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let n = urlencoding(it.next().unwrap_or(""));
            let v = urlencoding(it.next().unwrap_or(""));
            format!("{n}={v}")
        })
        .collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, kept.join("&"))
    }
}

/// Tolerant header extraction: solvers stash forged/auth headers under
/// various keys ("headers", "request.headers", "forged_headers",
/// "auth_headers") — collect every object-valued key whose name contains
/// "header" plus a curated set.
pub fn collect_headers(ev: &serde_json::Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    fn absorb(obj: &serde_json::Map<String, serde_json::Value>, out: &mut Vec<(String, String)>) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                if !out.iter().any(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
                    out.push((k.clone(), s.to_string()));
                }
            }
        }
    }
    // curated paths first
    for src in [&ev["headers"], &ev["request"]["headers"], &ev["forged_headers"], &ev["auth_headers"]] {
        if let Some(m) = src.as_object() {
            absorb(m, &mut out);
        }
    }
    // fuzzy: any *nested* object keyed with a name containing "header"
    if let Some(m) = ev.as_object() {
        for (k, v) in m {
            if k.to_lowercase().contains("header") {
                if let Some(inner) = v.as_object() {
                    absorb(inner, &mut out);
                }
            }
        }
    }
    out
}

/// Rescue pass: when a finding lacks expect/marker, mine candidate markers
/// from the solver's own observed evidence — flag{...} literals and
/// keyword-adjacent tokens. Verification still requires the marker to
/// appear on replay and differ from baseline, so this adds recall without
/// adding false positives.
pub fn extract_markers(ev: &serde_json::Value) -> Vec<String> {
    let mut found: Vec<String> = vec![];
    let mut scan = String::new();
    fn walk(v: &serde_json::Value, buf: &mut String, depth: u32) {
        if depth > 6 || buf.len() > 40_000 {
            return;
        }
        match v {
            serde_json::Value::String(s) => {
                buf.push_str(s);
                buf.push('\n');
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, buf, depth + 1)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, buf, depth + 1)),
            _ => {}
        }
    }
    walk(ev, &mut scan, 0);
    // flag{...} literals
    let mut rest = scan.as_str();
    while let Some(i) = rest.find("flag{") {
        let tail = &rest[i..];
        let end = tail.find('}').map(|e| e + 1).unwrap_or(0);
        if end > 5 && end < 80 {
            found.push(tail[..end].to_string());
        }
        rest = &tail[end.max(5)..];
    }
    // keyword-adjacent distinctive substrings
    const KW: &[&str] = &[
        "flag", "secret", "token", "password", "passwd", "internal_secret",
        "welcome admin", "admin ok", "api_key", "private key",
    ];
    for line in scan.lines() {
        let low = line.to_lowercase();
        if KW.iter().any(|k| low.contains(k)) {
            // pick a distinctive chunk: quoted string or word after ':'/'='
            for cand in line
                .split(|c: char| c == '"' || c == '\u{27}' || c == '=' || c == ':')
                .map(|t| t.trim().trim_matches(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-' || c == '{' || c == '}')))
                .filter(|t| t.len() >= 6 && t.len() <= 60)
            {
                if !cand.contains(' ') && !found.iter().any(|f| f == cand) {
                    found.push(cand.to_string());
                }
            }
        }
    }
    found.truncate(6);
    found
}

/// Shared marker-replay check: replay the evidence's declared request
/// (any method/params/headers/body) and require at least one marker
/// candidate — expect/marker field, or mined via extract_markers — to be
/// present in the replayed body AND absent from a plain-GET baseline.
/// Returns the reproduction description on success.
pub async fn marker_replay(
    probe: &crate::probe::ProbeClient,
    f: &crate::finding::Finding,
) -> Result<String, String> {
    let req = &f.evidence["request"];
    let url = req["url"]
        .as_str()
        .or_else(|| f.evidence["url"].as_str())
        .ok_or_else(|| "evidence missing request.url".to_string())?;
    let mut candidates: Vec<String> = f.evidence["expect"]
        .as_str()
        .or_else(|| f.evidence["marker"].as_str())
        .map(|m| vec![m.to_string()])
        .unwrap_or_else(|| extract_markers(&f.evidence));
    candidates.retain(|c| c.len() >= 4);
    if candidates.is_empty() {
        return Err("evidence missing expect/marker".into());
    }
    let method = req["method"].as_str().unwrap_or("GET");
    let hdr_src = req["headers"]
        .as_object()
        .or_else(|| f.evidence["headers"].as_object());
    let hdrs: Vec<(String, String)> = hdr_src
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let body = req["body"]
        .as_str()
        .or_else(|| f.evidence["body"].as_str())
        .map(String::from);
    // Solvers commonly embed the injection in request.url AND repeat it in
    // request.params. Split the URL: base (no query) + its own pairs, then
    // overlay evidence params so each key is sent exactly once.
    let (base_url, mut params) = match reqwest::Url::parse(url) {
        Ok(u) => {
            let mut pairs: std::collections::HashMap<String, String> = u
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let mut b = u;
            b.set_query(None);
            (b.to_string(), pairs)
        }
        Err(_) => (url.to_string(), std::collections::HashMap::new()),
    };
    if let Some(m) = req["params"].as_object() {
        for (k, v) in m {
            if let Some(s) = v.as_str() {
                params.insert(k.clone(), s.to_string());
            }
        }
    }
    let r = probe
        .send(method, &base_url, &params, &hdrs, body)
        .await
        .map_err(|_| "replay request failed".to_string())?;
    // Baseline must NOT contain the injected request: previously it replayed
    // the same URL (injection included) so the "absent in baseline" check
    // always failed for url-embedded payloads. Rebuild it as the same params
    // minus the evidence's injected parameter, with no forged headers.
    let injected = f.evidence["param"]
        .as_str()
        .map(|p| p.split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("").to_string());
    let mut base_params = params.clone();
    if let Some(p) = injected.as_deref().filter(|p| !p.is_empty()) {
        base_params.remove(p);
    } else {
        base_params.clear();
    }
    let base_body = probe
        .get2(&base_url, &base_params, &[])
        .await
        .map(|b| b.body)
        .unwrap_or_default();
    for expect in &candidates {
        if r.body.contains(expect.as_str()) && !base_body.contains(expect.as_str()) {
            return Ok(format!(
                "replayed {method} {url} -> marker '{expect}' in response, absent in baseline"
            ));
        }
    }
    Err(format!(
        "replayed request produced none of {} marker candidate(s)",
        candidates.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn param_sanitized() {
        assert_eq!(sanitize_param("u (query)"), "u");
        assert_eq!(sanitize_param("user_id"), "user_id");
    }

    #[test]
    fn rebuild_drops_polluted_target_param() {
        let u = rebuild_url("http://h/login?u=admin' --&keep=1", "u");
        assert_eq!(u, "http://h/login?keep=1");
    }

    #[test]
    fn extract_flag_and_secret_markers() {
        let ev = json!({
            "title": "RCE via eval",
            "observed_response": {"body": "Welcome admin! flag{hard-lab-win}"},
            "impact": {"note": "internal_secret=pepper123 leaked"}
        });
        let m = extract_markers(&ev);
        assert!(m.iter().any(|x| x.contains("flag{")), "{m:?}");
        assert!(m.iter().any(|x| x == "internal_secret"), "{m:?}");
    }
}
