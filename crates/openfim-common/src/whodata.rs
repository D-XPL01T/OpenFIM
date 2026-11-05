use serde::{Deserialize, Serialize};

/// Contextual forensic metadata about an acting process (Who-Data)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
    pub comm: Option<String>,
}

impl ProcessContext {
    /// Captures the current process's forensic context
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_process_resolution() {
        let ctx = ProcessContext::current();
        assert!(ctx.pid > 0);
        assert!(ctx.exe.is_some() || ctx.comm.is_some());
    }
}

