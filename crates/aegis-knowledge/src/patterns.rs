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
    pub fn few_shot(&self, n: usize) -> String {
        let mut ps = self.patterns.clone();
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
