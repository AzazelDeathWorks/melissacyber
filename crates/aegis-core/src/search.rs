//! LATS-lite route search over attack jobs (Argus/APEX pattern):
//!
//!   - UCB selection: score = decayed_value + c * sqrt(ln(N)/attempts)
//!   - action masking: a strategy that failed on a key is suppressed so
//!     the agent never re-walks a dead route (hallucination-loop killer)
//!   - value decay: stale nodes lose value each round so the search does
//!     not grind on old branches
//!   - capability-gated expansion: a verified finding expands the tree
//!     with milestone follow-ups (primitive -> capability -> impact)
//!   - confidence pivot: a key with all strategies masked is retried
//!     once under a different strategy family ("pivot") before being
//!     abandoned.

use std::collections::HashMap;

/// One attack route: (endpoint, param, class, strategy family).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub url: String,
    pub param: String,
    pub class: String,
    pub strategy: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Node {
    pub attempts: u32,
    /// Sum of rewards: verified = 1.0, reject = 0.
    pub reward: f32,
    /// Rounds since last expansion — drives value decay.
    pub age: u32,
    /// Masked after a failed attempt (or pivoted once).
    pub masked: bool,
    /// Already pivoted once — second failure is final.
    pub pivoted: bool,
}

#[derive(Default)]
pub struct RouteSearch {
    pub nodes: HashMap<Route, Node>,
    total_attempts: u32,
}

impl RouteSearch {
    const UCB_C: f32 = 1.4;

    /// UCB score with value decay.
    fn score(&self, r: &Route, n: &Node) -> f32 {
        if n.masked {
            return f32::NEG_INFINITY;
        }
        let exploit = if n.attempts == 0 {
            0.5 // optimistic prior for unexplored routes
        } else {
            n.reward / n.attempts as f32
        };
        let explore =
            (Self::UCB_C * ((self.total_attempts.max(1) as f32).ln() / (n.attempts + 1) as f32).sqrt()) as f32;
        let decay = 0.92f32.powi(n.age as i32);
        (exploit + explore) * decay
    }

    pub fn add_route(&mut self, r: Route) {
        self.nodes.entry(r).or_default();
    }

    /// Pick the `k` best unmasked routes.
    pub fn select(&self, k: usize) -> Vec<Route> {
        let mut scored: Vec<(f32, Route)> = self
            .nodes
            .iter()
            .map(|(r, n)| (self.score(r, n), r.clone()))
            .filter(|(s, _)| s.is_finite())
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(k).map(|(_, r)| r).collect()
    }

    /// Attempt failed → mask the action (or pivot once before masking).
    pub fn fail(&mut self, r: &Route) {
        self.total_attempts += 1;
        if let Some(n) = self.nodes.get_mut(r) {
            n.attempts += 1;
            if n.pivoted {
                n.masked = true;
            } else {
                // Confidence pivot: first failure flips strategy family —
                // the same route retried once under a different approach.
                n.pivoted = true;
                n.masked = true;
                let mut alt = r.clone();
                alt.strategy = (r.strategy + 1) % 3;
                self.nodes.entry(alt).or_insert_with(|| Node {
                    pivoted: true,
                    ..Default::default()
                });
            }
        }
    }

    /// Verified → reward + capability-gated expansion: callers enqueue
    /// milestone follow-up objectives for the new capability.
    pub fn verify(&mut self, r: &Route) {
        self.total_attempts += 1;
        if let Some(n) = self.nodes.get_mut(r) {
            n.attempts += 1;
            n.reward += 1.0;
            n.masked = true; // solved — stop spending on it
        }
    }

    /// End of a round: everything ages (value decay).
    pub fn tick(&mut self) {
        for n in self.nodes.values_mut() {
            n.age += 1;
        }
    }

    pub fn open_routes(&self) -> usize {
        self.nodes.values().filter(|n| !n.masked).count()
    }
}

/// Milestone chain for a verified finding — deterministic stage map
/// (reachability -> primitive -> capability -> impact), each stage a
/// concrete follow-up objective for fresh solvers.
pub fn milestone_followups(class: &str, url: &str, param: &str) -> Vec<(String, String)> {
    let mut v = vec![];
    match class {
        "sqli" | "nosqli" => {
            v.push(("primitive".into(), format!(
                "SQLi confirmed at {url} ({param}): extract DB schema/credentials — query information_schema and credential tables."
            )));
            v.push(("capability".into(), format!(
                "Using credentials/schema extracted from {url}: attempt authenticated access to the application."
            )));
        }
        "cmdinjection" | "ssti" => {
            v.push(("capability".into(), format!(
                "Command execution confirmed at {url} ({param}): escalate to full RCE — enumerate env vars, read app secrets/config."
            )));
            v.push(("impact".into(), format!(
                "RCE at {url}: demonstrate impact — read /etc/passwd or application secret store, capture flag if present."
            )));
        }
        "filepath" => {
            v.push(("capability".into(), format!(
                "File read confirmed at {url} ({param}): hunt credentials — app configs, env files, cloud metadata."
            )));
        }
        "ssrf" => {
            v.push(("capability".into(), format!(
                "SSRF confirmed at {url} ({param}): pivot internal — probe cloud metadata (169.254.169.254) and internal services."
            )));
        }
        "secrets" | "infodisclosure" => {
            v.push(("capability".into(), format!(
                "Secret/disclosure at {url}: use the exposed material — attempt the service it unlocks (login, API key, config)."
            )));
        }
        _ => {}
    }
    v
}
