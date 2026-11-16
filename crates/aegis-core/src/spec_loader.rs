//! Load agent specs from `agents/*.yaml` — user-editable definitions.

use crate::agent::{AgentKind, AgentSpec};
use std::path::Path;

fn parse_kind(s: &str) -> Option<AgentKind> {
    use AgentKind::*;
    Some(match s {
        "coordinator" => Coordinator,
        "recon_osint" => ReconOsint,
        "surface_mapper" => SurfaceMapper,
        "web_crawler" => WebCrawler,
        "api_mapper" => ApiMapper,
        "code_mapper" => CodeMapper,
        "cloud_recon" => CloudRecon,
        "solver_inj_sqli" => SolverInjSqli,
        "solver_inj_nosql" => SolverInjNosql,
        "solver_inj_cmd" => SolverInjCmd,
        "solver_inj_ssti" => SolverInjSsti,
        "solver_xss" => SolverXss,
        "solver_ssrf" => SolverSsrf,
        "solver_authn" => SolverAuthn,
        "solver_authz_idor" => SolverAuthzIdor,
        "solver_session_jwt" => SolverSessionJwt,
        "solver_deserialization" => SolverDeserialization,
        "solver_file_path" => SolverFilePath,
        "solver_xxe" => SolverXxe,
        "solver_smuggling" => SolverSmuggling,
        "solver_cors" => SolverCors,
        "solver_races_logic" => SolverRacesLogic,
        "solver_crypto" => SolverCrypto,
        "solver_ad_kerberos" => SolverAdKerberos,
        "solver_binary_pwn" => SolverBinaryPwn,
        "payload_forge" => PayloadForge,
        "chain_composer" => ChainComposer,
        "creds_manager" => CredsManager,
        "critic" => Critic,
        "dedup_triage" => DedupTriage,
        "summarizer" => Summarizer,
        "report_writer" => ReportWriter,
        "repro_qa" => ReproQa,
        "human_liaison" => HumanLiaison,
        "patch_dev" => PatchDev,
        "retest" => Retest,
        "detection_eng" => DetectionEng,
        "replay" => Replay,
        "hardening_auditor" => HardeningAuditor,
        "vaccine_orchestrator" => VaccineOrchestrator,
        _ => return None,
    })
}

/// Load all specs from a directory of yaml files.
pub fn load_dir(dir: &Path) -> anyhow::Result<Vec<AgentSpec>> {
    let mut specs = vec![];
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            let v: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(&path)?)?;
            let kind = parse_kind(v["kind"].as_str().unwrap_or(""))
                .ok_or_else(|| anyhow::anyhow!("{}: unknown kind", path.display()))?;
            specs.push(AgentSpec {
                kind,
                model_role: v["model_role"].as_str().unwrap_or("solver").into(),
                tools: v["tools"]
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|t| t.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                prompt_template: v["prompt_template"].as_str().unwrap_or("").into(),
                max_turns: v["max_turns"].as_u64().unwrap_or(40) as u32,
            });
        }
    }
    Ok(specs)
}
