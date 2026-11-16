//! Role-based routing: `models.yaml` maps agent roles to provider/model
//! specs; keys come from env and never hit disk or logs.
//!
//! Spec formats:
//!   anthropic/<model>     → api.anthropic.com     (ANTHROPIC_API_KEY)
//!   openai/<model>        → api.openai.com        (OPENAI_API_KEY)
//!   openrouter/<model>    → openrouter.ai         (OPENROUTER_API_KEY)
//!   ollama/<model>        → localhost:11434       (no key)
//!   custom|<base>/<model> → any OpenAI-compatible (AEGIS_CUSTOM_API_KEY)
//!
//! AEGIS_BASE_<PROVIDER> overrides the endpoint (vLLM, LM Studio, proxies).

use crate::anthropic::AnthropicProvider;
use crate::openai::OpenAiProvider;
use crate::provider::{LlmProvider, ProviderError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    #[serde(default)]
    pub role: String,
    /// e.g. "anthropic/claude-opus-4.5", "ollama/whiterabbitneo-70b"
    pub model: String,
    #[serde(default)]
    pub fallback: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ModelRouter {
    pub assignments: BTreeMap<String, RoleAssignment>,
}

fn env_key(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Parse a model spec into a provider instance.
pub fn build_provider(spec: &str) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    if let Some(rest) = spec.strip_prefix("custom|") {
        // base may contain "https://…" — split on the LAST '/'.
        let (base, model) = rest.rsplit_once('/').unwrap_or(("", ""));
        if base.is_empty() || model.is_empty() {
            return Err(ProviderError::NotConfigured(format!(
                "custom spec needs custom|<base_url>/<model>, got {spec}"
            )));
        }
        return Ok(Arc::new(OpenAiProvider::new(
            model,
            base,
            env_key("AEGIS_CUSTOM_API_KEY"),
        )));
    }

    let (provider, model) = spec.split_once('/').ok_or_else(|| {
        ProviderError::NotConfigured(format!("bad spec '{spec}' — want provider/model"))
    })?;

    let env_base = |name: &str| env_key(&format!("AEGIS_BASE_{name}"));

    match provider {
        "anthropic" => {
            let key = env_key("ANTHROPIC_API_KEY")
                .or_else(|| env_key("AEGIS_ANTHROPIC_API_KEY"))
                .ok_or(ProviderError::Auth)?;
            Ok(Arc::new(AnthropicProvider::new(model, key)))
        }
        "openai" => {
            let key = env_key("OPENAI_API_KEY")
                .or_else(|| env_key("AEGIS_OPENAI_API_KEY"))
                .ok_or(ProviderError::Auth)?;
            Ok(Arc::new(OpenAiProvider::new(
                model,
                env_base("OPENAI").unwrap_or_else(|| "https://api.openai.com/v1".into()),
                Some(key),
            )))
        }
        "openrouter" => {
            let key = env_key("OPENROUTER_API_KEY")
                .or_else(|| env_key("AEGIS_OPENROUTER_API_KEY"))
                .ok_or(ProviderError::Auth)?;
            Ok(Arc::new(OpenAiProvider::new(
                model,
                env_base("OPENROUTER")
                    .unwrap_or_else(|| "https://openrouter.ai/api/v1".into()),
                Some(key),
            )))
        }
        "ollama" => Ok(Arc::new(OpenAiProvider::new(
            model,
            env_base("OLLAMA").unwrap_or_else(|| "http://localhost:11434/v1".into()),
            env_key("OLLAMA_API_KEY"),
        ))),
        other => Err(ProviderError::NotConfigured(format!(
            "unknown provider '{other}' — supported: anthropic, openai, openrouter, ollama, custom|<base>/<model>"
        ))),
    }
}

impl ModelRouter {
    /// Load role assignments from a models.yaml (flat role: spec map or
    /// role: {model, fallback} form).
    pub fn from_yaml(text: &str) -> anyhow::Result<Self> {
        let raw: BTreeMap<String, serde_yaml::Value> = serde_yaml::from_str(text)?;
        let mut assignments = BTreeMap::new();
        for (role, v) in raw {
            let ra = match v {
                serde_yaml::Value::String(spec) => RoleAssignment {
                    role: role.clone(),
                    model: spec,
                    fallback: vec![],
                },
                other => serde_yaml::from_value(other)?,
            };
            assignments.insert(role, ra);
        }
        Ok(Self { assignments })
    }

    pub fn resolve(&self, role: &str) -> Option<&RoleAssignment> {
        self.assignments
            .get(role)
            .or_else(|| self.assignments.get("default"))
    }

    /// Instantiate the provider chain for a role (primary + fallbacks).
    pub fn provider_for(
        &self,
        role: &str,
    ) -> Result<Vec<Arc<dyn LlmProvider>>, ProviderError> {
        let ra = self
            .resolve(role)
            .ok_or_else(|| ProviderError::NotConfigured(role.into()))?;
        let mut chain = vec![build_provider(&ra.model)?];
        for f in &ra.fallback {
            if let Ok(p) = build_provider(f) {
                chain.push(p);
            }
        }
        Ok(chain)
    }
}
