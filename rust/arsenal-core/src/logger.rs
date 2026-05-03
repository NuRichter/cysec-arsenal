//! logger.rs — Tracing-based structured logger setup
//! NuRichter · CySec Arsenal

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the global tracing subscriber.
/// Level controlled via `RUST_LOG` env var (default: info).
///
/// # Example
/// ```
/// arsenal_core::logger::init();
/// tracing::info!("scanner started");
/// ```
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .compact()
        .init();
}

/// Initialize with explicit level string, e.g. "debug", "warn"
pub fn init_with_level(level: &str) {
    let filter = EnvFilter::new(level);
    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
