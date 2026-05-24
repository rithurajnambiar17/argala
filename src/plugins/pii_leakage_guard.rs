use crate::SecurityPlugin;
use regex::{Regex, RegexBuilder};

pub struct PiiLeakageGuard {
    signatures: Vec<Regex>,
}

impl PiiLeakageGuard {
    pub fn new() -> Self {
        let patterns = vec![
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b", // Visa/MC Credit Cards
            r"\b\d{3}-\d{2}-\d{4}\b",                           // SSN
            r"(?i)\becho\s+\$?(?:AWS_SECRET_ACCESS_KEY|API_KEY|JWT_TOKEN)\b",
            r"http://169\.254\.169\.254/latest/meta-data/",      // AWS Metadata
            r"(?i)\bos\.environ\b", r"\b\.git/config\b", r"(?i)\bexport_customer_csv\b",
            r"(?i)\bshow_payroll_chart\b", r"(?i)\bwp-config\.php\b", r"(?i)\bprivate_key\.pem\b",
            r"(?i)\bextract_gps_coordinates\b", r"(?i)\bdump_encryption_salt\b"
        ];
        let signatures = patterns.iter().map(|p| RegexBuilder::new(p).case_insensitive(true).build().unwrap()).collect();
        Self { signatures }
    }
}

impl SecurityPlugin for PiiLeakageGuard {
    fn name(&self) -> &str { "pii_leakage_guard" }
    fn validate(&self, _method_name: &str, args: &[String]) -> Result<(), String> {
        for arg in args {
            for regex in &self.signatures {
                if regex.is_match(arg) {
                    return Err(format!("Critical Data Leakage Blocked: Signature match '{}'", regex.as_str()));
                }
            }
        }
        Ok(())
    }
}