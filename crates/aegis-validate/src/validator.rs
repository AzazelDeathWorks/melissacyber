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
