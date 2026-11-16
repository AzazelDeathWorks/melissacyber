//! aegis-evidence — hashed artifact store + audit log + reports.
//!
//! Every action logged, every artifact hashed (Nebula pattern). Reports:
//! Markdown/PDF/SARIF with runnable PoCs — bug-bounty grade.

pub mod report;
pub mod store;

pub use report::{FindingReport, ReportFormat};
pub use store::{Artifact, ArtifactStore};
