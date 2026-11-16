//! Agent lifecycle primitives.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type AgentId = Uuid;

/// The ~40 agent types in the roster, grouped by layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentKind {
    // Layer 0
    Coordinator,
    // Layer 1 — discovery
    ReconOsint,
    SurfaceMapper,
    WebCrawler,
    ApiMapper,
    CodeMapper,
    CloudRecon,
    // Layer 2 — solvers (one vulnerability class each)
    SolverInjSqli,
    SolverInjNosql,
    SolverInjCmd,
    SolverInjSsti,
    SolverXss,
    SolverSsrf,
    SolverAuthn,
    SolverAuthzIdor,
    SolverSessionJwt,
    SolverDeserialization,
    SolverFilePath,
    SolverXxe,
    SolverSmuggling,
    SolverCors,
    SolverRacesLogic,
    SolverCrypto,
    SolverAdKerberos,
    SolverBinaryPwn,
    // Layer 3 — support
    PayloadForge,
    ChainComposer,
    CredsManager,
    Critic,
    DedupTriage,
    Summarizer,
    ReportWriter,
    ReproQa,
    HumanLiaison,
    // Layer 4 — blue team
    PatchDev,
    Retest,
    DetectionEng,
    Replay,
    HardeningAuditor,
    VaccineOrchestrator,
}

/// Static definition of an agent type: role, prompt template, tool allowlist,
/// model profile. Loaded from `agents/*.yaml` — user-editable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSpec {
    pub kind: AgentKind,
    pub model_role: String,
    pub tools: Vec<String>,
    pub prompt_template: String,
    pub max_turns: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    Born,
    Running,
    Debriefed,
    Retired,
}

/// A live agent instance. Solvers are born fresh per task and retired;
/// the coordinator persists for the engagement.
pub trait Agent: Send {
    fn id(&self) -> AgentId;
    fn kind(&self) -> AgentKind;
    fn state(&self) -> AgentState;
}
