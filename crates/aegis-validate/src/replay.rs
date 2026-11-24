//! Generic deterministic replay validator — covers FindingClass::Other
//! (custom exploit chains, auth-forged sinks, eval RCE, flag capture).
//!
//! Evidence shape:
//!   { "request": {"method","url","headers":{...},"body"},
//!     "expect": "<marker>" }
//! We replay it (any method/body) and require: marker present AND absent
//! from a baseline GET without exploit context.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::Validator;
use crate::verdict::Verdict;

pub struct ReplayValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for ReplayValidator {
    fn class(&self) -> FindingClass {
        FindingClass::Other
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        match crate::validator::marker_replay(&self.probe, f).await {
            Ok(reproduction) => Verdict::Verified { reproduction },
            Err(reason) => Verdict::Rejected { reason },
        }
    }
}

/// The generic marker-replay check bound to a specific class — used to
/// cover classes that have no dedicated validator yet (Authn, Nosqli,
/// Smuggling, Crypto, Crash) instead of dropping those findings.
pub struct ClassBoundReplayValidator {
    pub probe: ProbeClient,
    pub cls: FindingClass,
}

#[async_trait::async_trait]
impl Validator for ClassBoundReplayValidator {
    fn class(&self) -> FindingClass {
        self.cls
    }
    async fn validate(&self, f: &Finding) -> Verdict {
        match crate::validator::marker_replay(&self.probe, f).await {
            Ok(reproduction) => Verdict::Verified {
                reproduction: format!("{reproduction} (generic replay — no dedicated {:?} validator)", self.cls),
            },
            Err(reason) => Verdict::Rejected { reason },
        }
    }
}

