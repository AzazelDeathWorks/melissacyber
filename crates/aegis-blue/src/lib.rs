//! aegis-blue — the closed red->blue loop nobody else ships:
//! finding -> patch -> retest -> detection rule -> replay verification
//! ("offensive vaccine").

pub mod detection;
pub mod patch;
pub mod replay;

pub use detection::{DetectionRule, RuleFormat};
pub use patch::PatchProposal;
pub use replay::ReplayResult;
