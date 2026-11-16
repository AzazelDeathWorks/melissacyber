//! aegis-blue — the closed red->blue loop nobody else ships:
//! finding -> patch -> retest -> detection rule -> replay verification
//! ("offensive vaccine").

pub mod detection;
pub mod vaccine;
pub mod patch;
pub mod replay;

pub use detection::{sigma_for, sigma_matches, DetectionRule, RuleFormat};
pub use vaccine::{run_blue, BlueReport};
pub use patch::PatchProposal;
pub use replay::ReplayResult;
