//! aegis-validate — the zero-false-positive layer (XBOW's secret).
//!
//! Validators are non-AI code. An agent's candidate finding is only a
//! rumor until a validator independently reproduces it: canary tokens,
//! OOB interaction (own interactsh-class server), request replay,
//! sanitizer/crash checks. Nothing enters the report unverified.

pub mod finding;
pub mod verdict;
pub mod validator;

pub use finding::{Finding, FindingClass, Severity};
pub use verdict::Verdict;
pub use validator::{Validator, ValidatorRegistry};
