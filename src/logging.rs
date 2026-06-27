use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

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
    std::env::var(ENV_DEBUG).is_ok_and(|v| !v.is_empty())
        || std::env::var(ENV_VERBOSE).is_ok_and(|v| !v.is_empty())
}

pub fn format_log_timestamp(timestamp: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(timestamp)
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

pub fn logfmt_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::logging::verbose_enabled() {
            println!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn log_timestamp_is_single_field_rfc3339() {
        let timestamp = UNIX_EPOCH + Duration::from_nanos(1_234_567_890);

        assert_eq!(
            format_log_timestamp(timestamp),
            "1970-01-01T00:00:01.234567890Z"
        );
    }

    #[test]
    fn logfmt_string_escapes_delimiters() {
        assert_eq!(
            logfmt_string("hello \"there\"\nnext\\tab\tend"),
            "\"hello \\\"there\\\"\\nnext\\\\tab\\tend\""
        );
    }
}
