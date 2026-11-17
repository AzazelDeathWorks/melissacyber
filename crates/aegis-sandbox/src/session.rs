//! Shared session store: cookies captured by auth_login, keyed by host.
//! Held jointly by the tool-facing HTTP client and the validator probe
//! so findings found post-auth replay with the same session.

use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct SessionStore {
    pub cookies: HashMap<String, String>,
}
