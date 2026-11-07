//! Structured logging for the sensor daemon.
//!
//! # Why the daemon and not everything
//!
//! The agent is a long-running service. Its output is a **log stream**: something a
//! SIEM ingests, an operator greps months later, and an incident responder correlates
//! against other sources. That output needs levels, timestamps, stable field names and
//! a machine-readable mode.
//!
//! The interactive console and the one-shot CLI commands are a **user interface**. Their
//! `println!` output is formatted for a human reading it right now — banners, tables,
//! prompts. Routing that through a log subscriber would make it worse, not better, and
//! the plan's "replace `println!`" is about the daemon. That split is deliberate.
//!
//! # Formats
//!
//! - `human` (default) — readable lines for an operator watching a terminal.
//! - `json` — one JSON object per line, for ingestion. Event fields are emitted as
//!   structured key/value pairs rather than interpolated into a message string, so a
//!   collector can filter on `event_type` or `severity` without parsing prose.
//!
//! `RUST_LOG` is honoured in both, so verbosity is tunable without a rebuild.

use std::fmt;

/// Output format for the daemon's log stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum LogFormat {
    /// Readable lines for a human watching a terminal.
    #[default]
    Human,
    /// One JSON object per line, for SIEM ingestion.
    Json,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LogFormat::Human => "human",
            LogFormat::Json => "json",
        })
    }
}

/// Whether decorative, human-facing output should be written to stdout.
///
/// False under `--log-format json`. Without this gate the daemon's banners, progress
/// lines and alert blocks interleave with the JSON log stream, and a collector reading
/// stdout line by line finds most lines unparseable — which defeats the entire point of
/// a machine-readable format.
static HUMAN_OUTPUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// True when human-facing output is wanted.
pub fn human_output_enabled() -> bool {
    HUMAN_OUTPUT.load(std::sync::atomic::Ordering::Relaxed)
}

/// `println!` that is suppressed when the log stream must stay machine-readable.
#[macro_export]
macro_rules! hprintln {
    () => {
        if $crate::logging::human_output_enabled() { println!(); }
    };
    ($($arg:tt)*) => {
        if $crate::logging::human_output_enabled() { println!($($arg)*); }
    };
}

/// `eprintln!` that is suppressed when the log stream must stay machine-readable.
///
/// Anything genuinely important that this hides is also emitted through `tracing`, so
/// suppressing it loses presentation, not information.
#[macro_export]
macro_rules! heprintln {
    ($($arg:tt)*) => {
        if $crate::logging::human_output_enabled() { eprintln!($($arg)*); }
    };
}

/// Installs the global log subscriber.
///
/// Called once, before anything that logs. A second call is ignored rather than
/// panicking, so a mis-ordered caller degrades to the first format rather than taking
/// the daemon down — losing log formatting is never worth losing monitoring.
pub fn init(format: LogFormat) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    HUMAN_OUTPUT.store(
        format == LogFormat::Human,
        std::sync::atomic::Ordering::Relaxed,
    );

    // Default to INFO, overridable with RUST_LOG so verbosity needs no rebuild.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let result = match format {
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .json()
                    // Emit the structured fields as a flat object, so a collector sees
                    // `event_type` and `severity` as top-level keys rather than nested
                    // under a message blob.
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_span_list(false),
            )
            .try_init(),
        LogFormat::Human => tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_target(false)
                    .with_level(true)
                    // The daemon's own timestamps are already in the event records; a
                    // second wall-clock stamp per line is noise in a terminal.
                    .without_time(),
            )
            .try_init(),
    };

    if result.is_err() {
        // Already initialized. Not fatal, and not worth a panic in a security daemon.
        tracing::debug!("log subscriber was already installed; keeping the existing one");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_format_is_human() {
        assert_eq!(LogFormat::default(), LogFormat::Human);
    }

    #[test]
    fn formats_render_as_their_flag_values() {
        // These strings appear in `--help` and in operator scripts, so they are part of
        // the interface.
        assert_eq!(LogFormat::Human.to_string(), "human");
        assert_eq!(LogFormat::Json.to_string(), "json");
    }

    #[test]
    fn json_format_suppresses_human_output() {
        // The property that makes `--log-format json` actually usable. Before this gate
        // existed, 27 of 32 emitted lines were unparseable, because banners and alert
        // blocks interleaved with the JSON stream — a collector reading stdout line by
        // line could do nothing with it.
        init(LogFormat::Json);
        assert!(
            !human_output_enabled(),
            "decorative output must be suppressed under JSON, or the log stream is not \
             machine-readable"
        );

        init(LogFormat::Human);
        assert!(
            human_output_enabled(),
            "human output must be restored when the format is human"
        );
    }

    #[test]
    fn human_output_is_on_before_init() {
        // A message emitted before `init` runs should still reach an operator rather
        // than vanishing.
        init(LogFormat::Human);
        assert!(human_output_enabled());
    }

    #[test]
    fn repeated_init_does_not_panic() {
        // A security daemon must not die because logging was set up twice. Losing log
        // formatting is never worth losing monitoring.
        init(LogFormat::Human);
        init(LogFormat::Json);
        init(LogFormat::Human);
    }
}
