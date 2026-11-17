use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    Sqli,
    Nosqli,
    CmdInjection,
    Ssti,
    Xss,
    Ssrf,
    Authn,
    AuthzIdor,
    SessionJwt,
    Deserialization,
    FilePath,
    Xxe,
    Smuggling,
    Cors,
    Race,
    Crypto,
    Crash,
    InfoDisclosure,
    OpenRedirect,
    HostHeader,
    Secrets,
    Csrf,
    FileUpload,
    BusinessLogic,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub class: FindingClass,
    pub severity: Severity,
    pub title: String,
    /// Agent-supplied evidence: requests, payloads, observations.
    pub evidence: serde_json::Value,
    /// Populated only by a validator — never by an agent.
    pub verified: bool,
}
