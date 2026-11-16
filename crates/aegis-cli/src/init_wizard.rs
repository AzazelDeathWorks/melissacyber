//! `aegis init` — interactive scope/RoE wizard -> scope.yaml.
//! Non-interactive when --target and --out are given (CI-friendly).

use aegis_scope::{Roe, Scope, Target, TargetKind};
use std::io::{BufRead, Write};
use std::path::PathBuf;

fn prompt(label: &str, default: &str) -> String {
    print!("{label} [{default}]: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return default.into();
    }
    let line = line.trim();
    if line.is_empty() { default.into() } else { line.into() }
}

pub async fn run(target: Option<String>, out: Option<PathBuf>) -> anyhow::Result<()> {
    let target = target.unwrap_or_else(|| prompt("Target (url | repo path | cidr)", "http://localhost:3000"));

    let kind = if target.starts_with("http") {
        TargetKind::WebApp
    } else if target.contains('/') && std::path::Path::new(&target).exists() {
        TargetKind::Repository
    } else {
        TargetKind::IpRange
    };
    let workspace_path = if matches!(kind, TargetKind::Repository | TargetKind::LocalCode) {
        Some(target.clone())
    } else {
        None
    };

    // Egress allowlist: target host + anything the user adds.
    let mut egress = vec![];
    if let Ok(u) = url::Url::parse(&target) {
        if let Some(h) = u.host_str() {
            egress.push(h.to_string());
        }
    } else {
        egress.push(target.clone());
    }
    let extra = prompt("Extra egress domains (comma-separated, empty for none)", "");
    for e in extra.split(',') {
        let e = e.trim();
        if !e.is_empty() {
            egress.push(e.to_string());
        }
    }

    let authz = prompt(
        "Authorization statement (required — attests you may test these assets)",
        "I am authorized to test the assets in this scope",
    );

    let scope = Scope {
        targets: vec![Target { kind, value: target, workspace_path }],
        egress_allow: egress,
        roe: Roe {
            authorization_statement: Some(authz),
            ..Roe::default()
        },
    };

    // Authorization gate: refuse to write a scope without attestation.
    if scope.roe.authorization_statement.is_none() {
        anyhow::bail!("refusing to write scope.yaml without an authorization statement");
    }

    let out = out.unwrap_or_else(|| PathBuf::from("scope.yaml"));
    std::fs::write(&out, serde_yaml::to_string(&scope)?)?;
    println!("wrote {} — review it, then: aegis run --scope {}", out.display(), out.display());
    Ok(())
}
