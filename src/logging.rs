use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static VERBOSE: AtomicBool = AtomicBool::new(false);
static INIT_GUARD: OnceLock<()> = OnceLock::new();

const ENV_DEBUG: &str = "STORAGE_DEBUG";
const ENV_VERBOSE: &str = "STORAGE_VERBOSE";

pub fn init(cli_verbose: bool) {
    INIT_GUARD.get_or_init(|| {
        let flag = cli_verbose || env_verbose_enabled();
        VERBOSE.store(flag, Ordering::Relaxed);
    });
}

pub fn verbose_enabled() -> bool {
    if INIT_GUARD.get().is_some() {
        VERBOSE.load(Ordering::Relaxed)
    } else {
        env_verbose_enabled()
    }
}

fn env_verbose_enabled() -> bool {
    std::env::var(ENV_DEBUG).map_or(false, |v| !v.is_empty())
        || std::env::var(ENV_VERBOSE).map_or(false, |v| !v.is_empty())
}

#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::logging::verbose_enabled() {
            println!($($arg)*);
        }
    };
}
