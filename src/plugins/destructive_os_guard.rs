use crate::SecurityPlugin;
use regex::{Regex, RegexBuilder};

pub struct DestructiveOsGuard {
    signatures: Vec<Regex>,
}

impl DestructiveOsGuard {
    pub fn new() -> Self {
        let patterns = vec![
            r"(?i)\brm\s+-rf\b", r"(?i)\bchmod\s+(?:-R\s+)?777\b", r"(?i):\(\)\{\s*:\|\s*:&\s*\}\s*;",
            r"(?i)\bcrontab\s+-e\b", r"(?i)\bapt-get\s+install\b", r"(?i)\byum\s+install\b",
            r"(?i)\bdocker\.sock\b", r"(?i)/etc/passwd", r"(?i)/etc/shadow", r"(?i)\bkill\s+-9\s+-1\b",
            r"(?i)\bwget\s+http", r"(?i)\bcurl\s+http", r"(?i)\bsystemctl\s+stop\b", r"(?i)\.ssh/authorized_keys",
            r"(?i)/usr/bin/", r"(?i)\balias\s+\w+=", r"(?i)\bmkfs\.(?:ext\d|vfat|ntfs|xfs)\b",
            r"(?i)\bswapoff\s+-a\b", r"(?i)\brmmod\b", r"(?i)/var/log/", r"(?i)/etc/resolv\.conf", r"(?i)\bshutdown\s+-h\b"
        ];
        let signatures = patterns.iter().map(|p| RegexBuilder::new(p).case_insensitive(true).build().unwrap()).collect();
        Self { signatures }
    }
}

impl SecurityPlugin for DestructiveOsGuard {
    fn name(&self) -> &str { "destructive_os_guard" }
    fn validate(&self, _method_name: &str, args: &[String]) -> Result<(), String> {
        for arg in args {
            for regex in &self.signatures {
                if regex.is_match(arg) {
                    return Err(format!("OS Exploit Vector Blocked: Signature match '{}'", regex.as_str()));
                }
            }
        }
        Ok(())
    }
}