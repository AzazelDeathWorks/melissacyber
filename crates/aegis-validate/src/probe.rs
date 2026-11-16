//! Shared HTTP probe for validators — pure code, no AI.

use aegis_sandbox::Allowlist;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub body: String,
    pub elapsed: Duration,
}

#[derive(Clone)]
pub struct ProbeClient {
    client: reqwest::Client,
    pub allow: Allowlist,
}

impl ProbeClient {
    pub fn new(proxy: Option<&str>) -> anyhow::Result<Self> {
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .danger_accept_invalid_certs(true);
        if let Some(p) = proxy {
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
        Ok(Self {
            client: b.build()?,
            allow: Allowlist::new(&[]),
        })
    }

    pub fn with_allow(mut self, allow: Allowlist) -> Self {
        self.allow = allow;
        self
    }

    /// GET with query params. Refuses out-of-scope hosts — validators
    /// respect scope too.
    pub async fn get(
        &self,
        url: &str,
        params: &HashMap<String, String>,
    ) -> anyhow::Result<ProbeResponse> {
        let u = reqwest::Url::parse(url)?;
        let host = u.host_str().unwrap_or("").to_string();
        if !self.allow.allows(&host) {
            anyhow::bail!("validator refused out-of-scope host {host}");
        }
        let start = Instant::now();
        let resp = self.client.get(u).query(params).send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok(ProbeResponse {
            status,
            body,
            elapsed: start.elapsed(),
        })
    }
}
