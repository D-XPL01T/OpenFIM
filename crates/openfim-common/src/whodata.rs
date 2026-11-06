use serde::{Deserialize, Serialize};

/// Contextual forensic metadata about a process (Who-Data).
///
/// `is_attributed` is the critical field. It is true only when this context describes
/// the process that actually performed an observed filesystem modification. It is
/// false when the context merely describes some process that was resolved by PID —
/// including the sensor's own process.
///
/// The distinction matters because identifying the writer of a file requires the
/// kernel to tell us who it was: fanotify with `FAN_REPORT_PIDFD`, an eBPF probe, the
/// audit subsystem, or a Windows filesystem minifilter. A userspace watcher built on
/// inotify or `ReadDirectoryChangesW` receives the path that changed and nothing
/// about the actor. Filling these fields with the watcher's own identity and
/// presenting them as the actor would put a false attribution into every alert and
/// into the permanent audit trail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
    pub comm: Option<String>,
    /// True only when these fields describe the process responsible for an observed
    /// change. False when they describe an arbitrary or self-resolved process.
    #[serde(default)]
    pub is_attributed: bool,
}

impl ProcessContext {
    /// Whether this build can identify the process responsible for a filesystem change.
    ///
    /// Currently always false: the sensor is built on the cross-platform `notify`
    /// engine (inotify / `ReadDirectoryChangesW`), which reports *what* changed but
    /// not *who* changed it. This becomes true once a kernel attribution source is
    /// wired in.
    pub const fn attribution_available() -> bool {
        false
    }

    /// Context to attach to an observed filesystem event.
    ///
    /// Returns the sensor's own resolved context with `is_attributed` set to false
    /// while kernel attribution is unavailable, so callers can render and store it
    /// honestly rather than mislabelling it as the actor.
    pub fn for_observed_event() -> Self {
        let mut ctx = Self::current();
        ctx.is_attributed = Self::attribution_available();
        ctx
    }

    /// Captures the current process's forensic context.
    ///
    /// This describes the *calling* process, so `is_attributed` is false: it is useful
    /// for one-shot inspection output and diagnostics, not as event attribution.
    pub fn current() -> Self {
        Self::resolve_pid(std::process::id())
    }

    /// Resolves process identity for a given PID
    #[cfg(unix)]
    pub fn resolve_pid(pid: u32) -> Self {
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
            .ok()
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            });

        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
            .or_else(|| {
                exe.as_ref()
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .map(|n| n.to_string_lossy().to_string())
            });

        let mut uid = None;
        let mut ppid = None;
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        uid = val.parse::<u32>().ok();
                    }
                } else if line.starts_with("PPid:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        ppid = val.parse::<u32>().ok();
                    }
                }
            }
        }

        Self {
            pid,
            ppid,
            exe,
            cmdline,
            uid,
            comm,
            // Resolving a PID says nothing about whether that PID caused a given
            // filesystem change. Only an attribution source may set this.
            is_attributed: false,
        }
    }

    #[cfg(not(unix))]
    pub fn resolve_pid(pid: u32) -> Self {
        let exe = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().to_string());
        let comm = exe
            .as_ref()
            .and_then(|p| std::path::Path::new(p).file_name())
            .map(|n| n.to_string_lossy().to_string());
        let cmdline = std::env::args().collect::<Vec<_>>().join(" ");
        let uid = std::env::var("USERNAME").ok().map(|_| 1000);

        Self {
            pid,
            ppid: None,
            exe,
            cmdline: Some(cmdline),
            uid,
            comm,
            is_attributed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_resolution_is_never_marked_as_attribution() {
        // Guard against the sensor's own identity being presented as the actor.
        assert!(!ProcessContext::current().is_attributed);
        assert!(!ProcessContext::for_observed_event().is_attributed);
        assert!(!ProcessContext::resolve_pid(std::process::id()).is_attributed);
    }

    #[test]
    fn test_current_process_resolution() {
        let ctx = ProcessContext::current();
        assert!(ctx.pid > 0);
        assert!(ctx.exe.is_some() || ctx.comm.is_some());
    }
}
