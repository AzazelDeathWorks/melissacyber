//! `aegis pack import-atomic` — convert MITRE Atomic Red Team YAML
//! abilities into melissacyber playbook steps. Deterministic transform;
//! the imported corpus becomes purple-mode fodder on day one.

use serde_json::{json, Value};

/// Parse an Atomic Red Team test YAML into a normalized playbook doc.
/// Returns (name, technique, steps) where steps are shell commands.
pub fn import_atomic_yaml(text: &str) -> anyhow::Result<Value> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text)?;
    let name = doc["name"].as_str().unwrap_or("atomic-test").to_string();
    let technique = doc["attack_technique"]
        .as_str()
        .or_else(|| doc["technique"].as_str())
        .unwrap_or("unknown")
        .to_string();
    let mut steps = vec![];
    if let Some(tests) = doc["atomic_tests"].as_sequence() {
        for t in tests {
            let tname = t["name"].as_str().unwrap_or("test");
            if let Some(cmd) = t
                .get("executor")
                .and_then(|e| e.get("command"))
                .and_then(|c| c.as_str())
            {
                steps.push(json!({
                    "name": tname,
                    "command": cmd,
                    "executor": t["executor"]["name"].as_str().unwrap_or("sh"),
                }));
            }
        }
    }
    Ok(json!({
        "kind": "purple_playbook",
        "name": name,
        "technique": technique,
        "steps": steps,
        "source": "atomic-red-team",
    }))
}
