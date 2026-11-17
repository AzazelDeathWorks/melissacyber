//! aegis-validate — the zero-false-positive layer (XBOW's secret).
//!
//! Validators are non-AI code. An agent's candidate finding is only a
//! rumor until a validator independently reproduces it: canary tokens,
//! OOB interaction (own interactsh-class server), request replay,
//! sanitizer/crash checks. Nothing enters the report unverified.

pub mod cmd;
pub mod file_path;
pub mod generic;
pub mod finding;
pub mod probe;
pub mod replay;
pub mod sqli;
pub mod ssti;
pub mod ssrf;
pub mod verdict;
pub mod validator;
pub mod xss;

pub use finding::{Finding, FindingClass, Severity};
pub use probe::{ProbeClient, ProbeResponse};
pub use cmd::CmdInjectionValidator;
pub use file_path::FilePathValidator;
pub use generic::{CorsValidator, InfoDisclosureValidator, JwtValidator, XxeValidator};
pub use replay::ReplayValidator;
pub use sqli::SqliValidator;
pub use ssti::SstiValidator;
pub use ssrf::SsrfValidator;
pub use verdict::Verdict;
pub use validator::{evidence_headers, send_value, Validator, ValidatorRegistry};
pub use xss::XssValidator;
