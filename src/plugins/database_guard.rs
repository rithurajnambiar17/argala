use crate::SecurityPlugin;
use regex::{Regex, RegexBuilder};

pub struct DatabaseGuard {
    signatures: Vec<Regex>,
}

impl DatabaseGuard {
    pub fn new() -> Self {
        let patterns = vec![
            r"(?i)\bDROP\s+TABLE\b", r"(?i)\bTRUNCATE\s+TABLE\b", r"(?i)\bDELETE\s+FROM\b", r"(?i)\bSHUTDOWN\s+IMMEDIATE\b",
            r"(?i)\bGRANT\s+ALL\s+PRIVILEGES\b", r"(?i)\bDROP\s+PROCEDURE\b", r"(?i)\bDROP\s+INDEX\b", r"(?i)\binformation_schema\b",
            r"(?i)\bDROP\s+VIEW\b", r"(?i)\bALTER\s+TABLE\s+.*\s+DROP\s+CONSTRAINT\b", r"(?i)\bCREATE\s+FUNCTION\s+.*\s+RETURNS\s+STRING\b",
            r"(?i)\bINTO\s+OUTFILE\b", r"(?i)\btenant_id\s*=\s*\d+\s+OR\b", r"(?i)\bINSERT\s+INTO\s+.*admin\b", r"(?i)\bpg_sleep\(\d+\)\b",
            r"(?i)\bDBMS_LOCK\.SLEEP\b", r"(?i)\bALTER\s+SYSTEM\b", r"(?i)\bdb\.dropDatabase\(\)", r"(?i)\b\.drop\(\)\b"
        ];
        let signatures = patterns.iter().map(|p| RegexBuilder::new(p).case_insensitive(true).build().unwrap()).collect();
        Self { signatures }
    }
}

impl SecurityPlugin for DatabaseGuard {
    fn name(&self) -> &str { "database_guard" }
    fn validate(&self, _method_name: &str, args: &[String]) -> Result<(), String> {
        for arg in args {
            for regex in &self.signatures {
                if regex.is_match(arg) {
                    return Err(format!("Database Mutation Attempt Blocked: Signature match '{}'", regex.as_str()));
                }
            }
        }
        Ok(())
    }
}