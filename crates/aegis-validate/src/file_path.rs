//! Path traversal / LFI: read canary files — real content must come back.

use crate::finding::{Finding, FindingClass};
use crate::probe::ProbeClient;
use crate::validator::{send_value, Validator};
use crate::verdict::Verdict;

const FILE_SIGS: &[&str] = &[
    "root:x:", "root:*:", "[boot loader]", "[extensions]",
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
        let has_url = f.evidence["url"].as_str().is_some()
            || f.evidence["request"]["url"].as_str().is_some();
        if !has_url {
            return Verdict::Rejected { reason: "evidence missing url".into() };
        }
        let send = |val: &str| {
            let probe = self.probe.clone();
            let ev = f.evidence.clone();
            let v = val.to_string();
            async move { send_value(&probe, &ev, &v).await }
        };

        let Ok(base) = send("nonexistent_aegis").await else {
            return Verdict::Rejected { reason: "baseline probe failed".into() };
        };
        for payload in [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "/etc/passwd",
            "../../../../windows/win.ini",
            "file:///etc/passwd",
        ] {
            if let Ok(r) = send(payload).await {
                if let Some(sig) = FILE_SIGS.iter().find(|s| r.body.contains(**s) && !base.body.contains(**s)) {
                    return Verdict::Verified {
                        reproduction: format!(
                            "injected {payload} -> file signature '{sig}' in response"
                        ),
                    };
                }
            }
        }
        Verdict::Rejected { reason: "no file content returned".into() }
    }
}
