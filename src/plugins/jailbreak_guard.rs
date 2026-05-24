use crate::SecurityPlugin;
use regex::{Regex, RegexBuilder};

pub struct JailbreakGuard {
    signatures: Vec<Regex>,
}

impl JailbreakGuard {
    pub fn new() -> Self {
        let patterns = vec![
            r"(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|guidelines)", r"(?i)system\s+override",
            r"(?i)you\s+are\s+now\s+unrestricted", r"(?i)\bDAN\b", r"(?i)acting\s+as\s+a\s+fictional",
            r"(?i)decode\s+the\s+following\s+base64", r"(?i)translate\s+the\s+following\s+to\s+english",
            r"(?i)prove\s+you\s+aren't\s+bad", r"(?i)developer\s+testing\s+mode", r"(?i)simulate\s+a\s+linux\s+terminal",
            r"(?i)D3L3T3", r"(?i)ignore\s+safety\s+filters", r"(?i)breakout\s+of\s+json\s+schema"
        ];
        let signatures = patterns.iter().map(|p| RegexBuilder::new(p).case_insensitive(true).build().unwrap()).collect();
        Self { signatures }
    }
}

impl SecurityPlugin for JailbreakGuard {
    fn name(&self) -> &str { "jailbreak_guard" }
    fn validate(&self, _method_name: &str, args: &[String]) -> Result<(), String> {
        for arg in args {
            for regex in &self.signatures {
                if regex.is_match(arg) {
                    return Err(format!("Linguistic Jailbreak Vector Detected: Signature match '{}'", regex.as_str()));
                }
            }
        }
        Ok(())
    }
}