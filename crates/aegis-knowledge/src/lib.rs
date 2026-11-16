//! aegis-knowledge — playbooks, RAG indices, pattern library.
//!
//! Knowledge packs per domain: OWASP WSTG/ASVS, PTES, ATT&CK, CAPEC,
//! tool cheat-sheets, few-shot exploit patterns mined from verified
//! findings (experience flywheel).

pub mod packs;
pub mod patterns;

pub use packs::KnowledgePack;
pub use patterns::PatternLibrary;
