use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) mod metrics;
pub(crate) mod text;
pub(crate) mod words;

// current_time_ms returns current time as milliseconds
pub fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("could not get time")
        .as_millis() as i64
}
