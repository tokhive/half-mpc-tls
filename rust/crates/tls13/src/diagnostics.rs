//! Opt-in, redacted stage timings for native profiling and warm-up diagnosis.
//!
//! Set `TOKENHIVE_PROFILE_STAGES=1` before starting the process. Intervals include
//! asynchronous waiting and may nest. CPU deltas cover the whole process, including
//! concurrent work; neither nested nor overlapping intervals may be summed.
use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

static ENABLED: OnceLock<bool> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A profiling interval containing only fixed phase names and process metadata.
/// Ending an interval does not imply that the operation succeeded.
pub struct Phase {
    interval: Option<(u64, Instant)>,
    cpu: Option<cpu_time::ProcessTime>,
    provider: bool,
    name: &'static str,
    completed: bool,
}

impl Phase {
    /// Starts an interval if profiling was enabled when the process first used it.
    pub fn new(provider: bool, name: &'static str) -> Self {
        let interval = if *ENABLED
            .get_or_init(|| std::env::var("TOKENHIVE_PROFILE_STAGES").is_ok_and(|v| v == "1"))
        {
            Some((NEXT_ID.fetch_add(1, Ordering::Relaxed), Instant::now()))
        } else {
            None
        };
        let phase = Self {
            interval,
            cpu: interval.and_then(|_| cpu_time::ProcessTime::try_now().ok()),
            provider,
            name,
            completed: false,
        };
        phase.emit("begin");
        phase
    }

    /// Marks successful completion; cancellation or an early error remains distinct.
    pub fn finish(mut self) {
        self.completed = true;
    }

    fn emit(&self, event: &str) {
        let Some((id, start)) = self.interval else {
            return;
        };
        eprintln!(
            "{}",
            serde_json::json!({
                "type": "tokenhive_phase", "pid": std::process::id(), "id": id,
                "role": if self.provider { "provider" } else { "hub" },
                "phase": self.name, "event": event,
                "completed": self.completed,
                "unix_ns": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
                "elapsed_ns": start.elapsed().as_nanos(),
                "process_cpu_ns": self.cpu.and_then(|cpu| cpu.try_elapsed().ok()).map(|cpu| cpu.as_nanos()),
            })
        );
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        self.emit("end");
    }
}
