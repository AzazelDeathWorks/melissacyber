//! Shared HTTP probe for validators — pure code, no AI.
//! GET/POST/…, manual redirect following through the scope allowlist
//! (a 302 off-target must NOT be followed silently).

use aegis_sandbox::{Allowlist, RateLimiter, SessionStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub body: String,
    pub elapsed: Duration,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone)]
pub struct ProbeClient {
    client: reqwest::Client,
    pub allow: Allowlist,
    limiter: Option<Arc<RateLimiter>>,
    session: Option<Arc<Mutex<SessionStore>>>,
}

impl ProbeClient {
    pub fn new(proxy: Option<&str>) -> anyhow::Result<Self> {
        // Redirects are followed MANUALLY so every hop is scope-checked.
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .danger_accept_invalid_certs(true);
        if let Some(p) = proxy {
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
        Ok(Self {
            client: b.build()?,
            allow: Allowlist::new(&[]),
            limiter: None,
            session: None,
        })
    }

    pub fn with_allow(mut self, allow: Allowlist) -> Self {
        self.allow = allow;
        self
    }

    pub fn with_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    /// Share the engagement session store: cookies captured by auth_login
    /// are injected into replays for that host (post-auth validation)
    /// unless the evidence already sets a Cookie header.
    pub fn with_session(mut self, session: Arc<Mutex<SessionStore>>) -> Self {
        self.session = Some(session);
        self
    }

    /// GET with query params. Refuses out-of-scope hosts — validators
    /// respect scope too.
    pub async fn get(
        &self,
        url: &str,
        params: &HashMap<String, String>,
    ) -> anyhow::Result<ProbeResponse> {
        self.send("GET", url, params, &[], None).await
    }

    /// Same as `get`, but attaches evidence-supplied headers (e.g. an
    /// auth token the solver had to forge to reach the sink).
    pub async fn get2(
        &self,
        url: &str,
        params: &HashMap<String, String>,
        headers: &[(String, String)],
    ) -> anyhow::Result<ProbeResponse> {
        self.send("GET", url, params, headers, None).await
    }

    /// Full request: any method, optional body. Follows up to 5 redirects,
    /// checking each hop against the scope allowlist.
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        params: &HashMap<String, String>,
        headers: &[(String, String)],
        body: Option<String>,
    ) -> anyhow::Result<ProbeResponse> {
        let mut url = reqwest::Url::parse(url)?;
        let mut first = true;
        for hop in 0..6 {
            let host = url.host_str().unwrap_or("").to_string();
            if !self.allow.allows(&host) {
                anyhow::bail!("validator refused out-of-scope host {host}");
            }
            if let Some(l) = &self.limiter {
                l.wait().await;
            }
            let m: reqwest::Method = if first {
                method.parse().unwrap_or(reqwest::Method::GET)
            } else {
                reqwest::Method::GET // redirect follows are GET
            };
            let start = Instant::now();
            let mut req = self.client.request(m, url.clone());
            if first && !params.is_empty() {
                req = req.query(params);
            }
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str());
            }
            // Post-auth replay: inject stored session cookies when the
            // evidence did not set its own Cookie header.
            let has_cookie = headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("cookie"));
            if !has_cookie {
                if let Some(ck) = self
                    .session
                    .as_ref()
                    .and_then(|s| s.lock().unwrap().cookies.get(&host).cloned())
                {
                    req = req.header("cookie", ck);
                }
            }
            if first {
                if let Some(b) = &body {
                    req = req.body(b.clone());
                }
            }
            let resp = req.send().await?;
            let status = resp.status().as_u16();
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            if (300..400).contains(&status) && hop < 5 {
                if let Some(loc) = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    url = url.join(loc)?;
                    first = false;
                    continue;
                }
            }
            let body = resp.text().await.unwrap_or_default();
            return Ok(ProbeResponse {
                status,
                body,
                elapsed: start.elapsed(),
                headers: resp_headers,
            });
        }
        anyhow::bail!("too many redirects")
    }
}
