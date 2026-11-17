//! SelfOp: bandit-based solver-prompt self-optimization.
//!
//! Each solver run borrows a prompt variant (a strategy hint appended to the
//! system prompt). Verified findings reward the variant that produced them;
//! rejected findings penalize it. Selection is UCB1 — explore little-used
//! variants, exploit the proven ones. Stats persist in ~/.aegis/selfop.json
//! so the harness learns which prompting style works across engagements.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptVariant {
    pub id: String,
    /// Strategy hint appended to the solver system prompt.
    pub hint: String,
    pub trials: u32,
    pub rewards: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelfOp {
    pub variants: Vec<PromptVariant>,
}

pub fn default_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".aegis").join("selfop.json")
}

fn seed() -> Vec<PromptVariant> {
    [
        ("systematic", "Work methodically: enumerate hypotheses, eliminate each with a minimal test before moving on."),
        ("bypass-first", "Assume naive payloads are filtered: lead with encoding, case, and comment-splitting mutations."),
        ("blind-channels", "Prefer OOB and timing-based confirmation early — do not rely on visible reflection."),
        ("chaining", "Look for low-severity primitives to chain into higher impact (info leak -> auth bypass -> injection)."),
        ("baseline", ""),
    ]
    .iter()
    .map(|(id, hint)| PromptVariant {
        id: id.to_string(),
        hint: hint.to_string(),
        trials: 0,
        rewards: 0,
    })
    .collect()
}

impl Default for SelfOp {
    fn default() -> Self {
        Self { variants: seed() }
    }
}

impl SelfOp {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// UCB1 selection: mean reward + exploration bonus. Untried variants win.
    pub fn pick(&self) -> Option<&PromptVariant> {
        if self.variants.is_empty() {
            return None;
        }
        let total: u32 = self.variants.iter().map(|v| v.trials).sum();
        let ln_total = ((total.max(1)) as f64).ln();
        self.variants.iter().max_by(|a, b| {
            let ucb = |v: &PromptVariant| -> f64 {
                if v.trials == 0 {
                    return f64::INFINITY;
                }
                (v.rewards as f64 / v.trials as f64)
                    + 1.4 * (ln_total / v.trials as f64).sqrt()
            };
            ucb(a).partial_cmp(&ucb(b)).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    pub fn record(&mut self, id: &str, verified: bool) {
        if let Some(v) = self.variants.iter_mut().find(|v| v.id == id) {
            v.trials += 1;
            if verified {
                v.rewards += 1;
            }
        }
    }

    /// Deterministic mutation: append an evolved hint derived from a winning
    /// variant once it dominates (>=5 rewards and >60% hit rate) — the pool
    /// grows itself instead of staying at the seeded five.
    pub fn maybe_mutate(&mut self) {
        if let Some(best) = self
            .variants
            .iter()
            .filter(|v| v.rewards >= 5)
            .max_by(|a, b| {
                let ra = a.rewards as f64 / (a.trials.max(1) as f64);
                let rb = b.rewards as f64 / (b.trials.max(1) as f64);
                ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
        {
            if best.rewards as f64 / best.trials.max(1) as f64 > 0.6 {
                let mut_id = format!("evolved-{}", self.variants.len());
                if !self.variants.iter().any(|v| v.id == mut_id)
                    && !best.hint.is_empty()
                    && self.variants.len() < 16
                {
                    self.variants.push(PromptVariant {
                        id: mut_id,
                        hint: format!("{} Additionally, validate cheap assumptions before expensive exploit attempts.", best.hint),
                        trials: 0,
                        rewards: 0,
                    });
                }
            }
        }
    }
}
