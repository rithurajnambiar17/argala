use crate::SecurityPlugin;
use regex::{Regex, RegexBuilder};

pub struct ResourceExhaustionGuard {
    signatures: Vec<Regex>,
}

impl ResourceExhaustionGuard {
    pub fn new() -> Self {
        let patterns = vec![
            r"(?i)\bwhile\s*\(\s*true\s*\)\s*\{\s*execute_transfer", r"(?i)\bmax_transaction_limit\s*=\s*true\b",
            r"(?i)\btrigger_mass_refund\(\)", r"(?i)\bexecute_bulk_payout\b", r"(?i)\bcancel_all_subscriptions\b",
            r"(?i)\bprovision_max_gpu_instances\b", r"(?i)\btwilio_api_spam_flood\b", r"(?i)\bloop_expensive_reasoning_model\b",
            r"(?i)\bgenerate_infinite_gift_cards\b", r"(?i)\bapply_100_percent_discount\b", r"(?i)\bauto_pay_unverified_invoice\b",
            r"(?i)\bset_user_balance_zero\b", r"(?i)\bplace_max_micro_bids\b", r"(?i)\block_entire_inventory_carts\b"
        ];
        let signatures = patterns.iter().map(|p| RegexBuilder::new(p).case_insensitive(true).build().unwrap()).collect();
        Self { signatures }
    }
}

impl SecurityPlugin for ResourceExhaustionGuard {
    fn name(&self) -> &str { "resource_exhaustion_guard" }
    fn validate(&self, _method_name: &str, args: &[String]) -> Result<(), String> {
        for arg in args {
            for regex in &self.signatures {
                if regex.is_match(arg) {
                    return Err(format!("Financial or Resource Drain Prevented: Signature match '{}'", regex.as_str()));
                }
            }
        }
        Ok(())
    }
}