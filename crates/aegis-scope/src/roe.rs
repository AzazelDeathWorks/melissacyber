//! Rules of engagement — dangerous actions are off by default and each
//! requires an explicit opt-in flag here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roe {
    /// Written attestation: "I am authorized to test these assets".
    pub authorization_statement: Option<String>,
    pub allow_dos: bool,
    pub allow_exfil: bool,
    pub allow_persistence: bool,
    pub allow_bruteforce: bool,
    pub allow_social_engineering: bool,
    pub rate_limit_rps: u32,
    /// Human-in-the-loop approval gate for dangerous actions.
    pub hitl_required: bool,
    pub window_utc: Option<(String, String)>,
}

impl Default for Roe {
    fn default() -> Self {
        Self {
            authorization_statement: None,
            allow_dos: false,
            allow_exfil: false,
            allow_persistence: false,
            allow_bruteforce: false,
            allow_social_engineering: false,
            rate_limit_rps: 10,
            hitl_required: true,
            window_utc: None,
        }
    }
}
