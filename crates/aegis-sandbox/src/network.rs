//! Network isolation: `aegis-net` bridge + default-deny egress proxy.
//!
//! Scope enforcement lives at the network layer, not the prompt layer —
//! packets to out-of-scope hosts are dropped regardless of what the
//! agent tries (the gap Strix leaves open).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// Domains/IPs/CIDRs reachable by the attack box.
    pub allow: Vec<String>,
    /// Everything else is dropped at the proxy.
    pub default_deny: bool,
}

impl EgressPolicy {
    pub fn deny_all() -> Self {
        Self {
            allow: vec![],
            default_deny: true,
        }
    }
}
