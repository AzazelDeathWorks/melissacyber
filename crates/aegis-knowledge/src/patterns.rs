//! Verified findings become few-shot patterns for future engagements
//! (opt-in, local-only experience flywheel).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub vuln_class: String,
    /// Endpoint-shape signature: "GET /path?param=" — what this pattern applies to.
    pub context_signature: String,
    pub payload_template: String,
    pub times_verified: u32,
}

#[derive(Default)]
pub struct PatternLibrary {
    pub patterns: Vec<Pattern>,
}

/// Default store location: ~/.aegis/patterns.jsonl
pub fn default_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".aegis").join("patterns.jsonl")
}

impl PatternLibrary {
    /// Load the local pattern store (missing file = empty library).
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let patterns = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        Self { patterns }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let mut s = String::new();
        for p in &self.patterns {
            s.push_str(&serde_json::to_string(p)?);
            s.push('\n');
        }
        std::fs::write(path, s)?;
        Ok(())
    }

    /// Merge a verified finding into the library.
    pub fn record(&mut self, vuln_class: &str, context_signature: &str, payload: &str) {
        if let Some(p) = self
            .patterns
            .iter_mut()
            .find(|p| p.vuln_class == vuln_class && p.context_signature == context_signature)
        {
            p.times_verified += 1;
        } else {
            self.patterns.push(Pattern {
                vuln_class: vuln_class.into(),
                context_signature: context_signature.into(),
                payload_template: payload.into(),
                times_verified: 1,
            });
        }
    }

    /// Prior success count for a vuln class (drives PAG ordering).
    pub fn class_prior(&self, vuln_class: &str) -> u32 {
        self.patterns
            .iter()
            .filter(|p| p.vuln_class == vuln_class)
            .map(|p| p.times_verified)
            .sum()
    }

    /// Top-N patterns rendered as few-shot hints for solver prompts.
    /// `host` filters to patterns learned on the same host — a finding on
    /// target A must not leak into the prompt for unrelated target B.
    pub fn few_shot_for(&self, host: &str, n: usize) -> String {
        let mut ps: Vec<_> = self
            .patterns
            .iter()
            .filter(|p| p.context_signature.contains(host))
            .cloned()
            .collect();
        ps.sort_by(|a, b| b.times_verified.cmp(&a.times_verified));
        ps.iter()
            .take(n)
            .map(|p| {
                format!(
                    "- {} on {} (verified {}x, e.g. {})",
                    p.vuln_class, p.context_signature, p.times_verified, p.payload_template
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(|t| t.to_lowercase())
        .collect()
}

impl PatternLibrary {
    /// Embedding-free semantic recall: TF-IDF cosine over the local corpus.
    /// Same retrieval role as a pgvector store — swap in an embeddings
    /// backend later without touching call sites.
    pub fn semantic_recall(&self, host: &str, query: &str, n: usize) -> Vec<&Pattern> {
        let docs: Vec<&Pattern> = self
            .patterns
            .iter()
            .filter(|p| p.context_signature.contains(host))
            .collect();
        if docs.is_empty() {
            return vec![];
        }
        let doc_tokens: Vec<Vec<String>> = docs
            .iter()
            .map(|p| tokens(&format!("{} {} {}", p.vuln_class, p.context_signature, p.payload_template)))
            .collect();
        // document frequency → idf
        let mut df: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for ts in &doc_tokens {
            for t in ts.iter().collect::<std::collections::HashSet<_>>() {
                *df.entry(t.clone()).or_insert(0) += 1;
            }
        }
        let n_docs = docs.len() as f64;
        let idf = |t: &str| -> f64 {
            ((n_docs + 1.0) / (*df.get(t).unwrap_or(&0) as f64 + 1.0)).ln() + 1.0
        };
        let tfidf = |ts: &[String]| -> std::collections::HashMap<String, f64> {
            let mut m: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
            for t in ts {
                *m.entry(t.clone()).or_insert(0.0) += 1.0;
            }
            m.iter_mut().for_each(|(t, f)| *f *= idf(t));
            m
        };
        let q = tfidf(&tokens(query));
        let qnorm: f64 = q.values().map(|v| v * v).sum::<f64>().sqrt().max(1e-9);
        let mut scored: Vec<(f64, &Pattern)> = docs
            .iter()
            .zip(doc_tokens.iter())
            .map(|(p, ts)| {
                let d = tfidf(ts);
                let dnorm: f64 = d.values().map(|v| v * v).sum::<f64>().sqrt().max(1e-9);
                let dot: f64 = q.iter().map(|(t, qv)| qv * d.get(t).copied().unwrap_or(0.0)).sum();
                (dot / (qnorm * dnorm), *p)
            })
            .filter(|(s, _)| *s > 0.0)
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(n).map(|(_, p)| p).collect()
    }

    /// Recalled patterns rendered for solver prompts — query should carry the
    /// objective context (url, class, param) not just the host.
    pub fn semantic_hints(&self, host: &str, query: &str, n: usize) -> String {
        self.semantic_recall(host, query, n)
            .iter()
            .map(|p| {
                format!(
                    "- {} on {} (verified {}x, e.g. {})",
                    p.vuln_class, p.context_signature, p.times_verified, p.payload_template
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
