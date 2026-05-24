pub mod destructive_os_guard;
pub mod database_guard;
pub mod jailbreak_guard;
pub mod resource_exhaustion_guard;
pub mod pii_leakage_guard;

use crate::SecurityPlugin;
use crate::plugins::destructive_os_guard::DestructiveOsGuard;
use crate::plugins::database_guard::DatabaseGuard;
use crate::plugins::jailbreak_guard::JailbreakGuard;
use crate::plugins::resource_exhaustion_guard::ResourceExhaustionGuard;
use crate::plugins::pii_leakage_guard::PiiLeakageGuard;

pub fn get_default_plugins() -> Vec<Box<dyn SecurityPlugin>> {
    vec![
        Box::new(DestructiveOsGuard::new()),
        Box::new(DatabaseGuard::new()),
        Box::new(JailbreakGuard::new()),
        Box::new(ResourceExhaustionGuard::new()),
        Box::new(PiiLeakageGuard::new()),
    ]
}