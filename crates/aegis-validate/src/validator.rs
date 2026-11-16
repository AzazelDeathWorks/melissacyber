use crate::finding::{Finding, FindingClass};
use crate::verdict::Verdict;
use std::collections::BTreeMap;
use std::sync::Arc;

/// One validator per finding class. Pure code: canary injection,
/// OOB callback correlation, replay diffing. WASM plugins can extend.
#[async_trait::async_trait]
pub trait Validator: Send + Sync {
    fn class(&self) -> FindingClass;
    async fn validate(&self, finding: &Finding) -> Verdict;
}

#[derive(Default)]
pub struct ValidatorRegistry {
    validators: BTreeMap<String, Arc<dyn Validator>>,
}

impl ValidatorRegistry {
    pub fn register(&mut self, v: Arc<dyn Validator>) {
        self.validators.insert(format!("{:?}", v.class()), v);
    }

    pub fn get(&self, class: &FindingClass) -> Option<Arc<dyn Validator>> {
        self.validators.get(&format!("{class:?}")).cloned()
    }
}

/// Pull headers the solver used in its exploit (e.g. forged auth) out of
/// `evidence["headers"]` so validators replay with the same context.
pub fn evidence_headers(f: &crate::finding::Finding) -> Vec<(String, String)> {
    f.evidence["headers"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}
