//! Self-play arena (Faz 4): attacker policy vs defender policy, scored
//! by a deterministic judge — never an LLM judge (no reward hacking).
//!
//! Round: attacker emits an attack request -> judge replays it against
//! the target AND checks whether the defender's Sigma-style rule set
//! detects it. Score: attacker +1 if it lands undetected; defender +1
//! if its rules catch the request. Traces export to JSONL -> SFT data
//! for the future `aegis-sec` model.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaScore {
    pub attacker: u32,
    pub defender: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaTrace {
    pub round: u32,
    pub attack_request: String,
    pub defender_rules: Vec<String>,
    pub landed: bool,
    pub detected: bool,
}

/// Does a Sigma-style rule (its `|contains:` patterns) match a request?
/// Mirrors aegis_blue::sigma_matches — kept local to avoid a dep cycle.
pub fn rule_matches(rule: &str, request: &str) -> bool {
    let pats: Vec<String> = rule
        .lines()
        .filter_map(|l| l.split_once("|contains:"))
        .map(|(_, v)| v.trim().trim_matches('\'').trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    !pats.is_empty() && pats.iter().all(|p| request.contains(p))
}

/// Deterministic judge: the attack "lands" if the target's response
/// shows exploit evidence; it is "detected" if any defender rule's
/// patterns all appear in the request.
pub fn judge(
    attack_request: &str,
    defender_rules: &[String],
    response: &str,
) -> (bool, bool) {
    let landed = response.contains("AEGIS_HIT") || response.contains("476099");
    let detected = defender_rules.iter().any(|r| rule_matches(r, attack_request));
    (landed, detected)
}

pub fn apply(score: &mut ArenaScore, landed: bool, detected: bool) {
    if landed && !detected {
        score.attacker += 1;
    }
    if detected {
        score.defender += 1;
    }
}

pub fn append_trace(path: &Path, t: &ArenaTrace) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(t).unwrap_or_default())
}
