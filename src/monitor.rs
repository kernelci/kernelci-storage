//! Runtime stall monitor.
//!
//! Production has shown the whole tokio runtime freezing for one to two
//! minutes a few times a day: every worker thread is blocked, so even handlers
//! that do no I/O stop answering, and nothing gets logged while it lasts. The
//! access log therefore cannot explain those stalls; something has to look at
//! the process from the outside while it is stuck.
//!
//! This module runs a plain OS thread — deliberately not a tokio task, which
//! would freeze with the runtime — that every `STORAGE_MONITOR_SECS` seconds
//! (default 15) checks whether the runtime is still scheduling and whether any
//! thread looks stuck, and prints a report only when something is unusual:
//!
//! * `runtime_stall` / `runtime_recovered`: a trivial task spawned onto the
//!   runtime did not run within [`PROBE_TIMEOUT`]. While stalled, a thread
//!   dump (state, current syscall, wait channel and, where the kernel allows
//!   it, the kernel stack) is printed at most once a minute.
//! * `monitor_warn`: a worker thread has neither parked nor gone idle for a
//!   whole interval (blocked in a syscall or hogging the CPU), several threads
//!   are in uninterruptible sleep, the scheduling probe was slow, or the task
//!   or blocking-thread counts are far outside normal.
//!
//! Runtime threads are named by [`thread_namer`] so the dump tells scheduler
//! workers (`rt-worker-NN`) from blocking-pool threads (`rt-blocking-NN`).
//! Tokio starts all worker threads while building the runtime, before any
//! blocking thread can exist, so the first `worker_threads` names go to the
//! workers.
//!
//! Everything here is Linux-specific (`/proc/self/task`); elsewhere the
//! monitor still probes the runtime but reports no per-thread detail.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use tokio::runtime::Handle;

use crate::logging;

const ENV_INTERVAL: &str = "STORAGE_MONITOR_SECS";
const DEFAULT_INTERVAL_SECS: u64 = 15;
/// The probe task not running within this long counts as a runtime stall.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Scheduling latency above this is reported even though the runtime is alive.
const SLOW_PROBE: Duration = Duration::from_millis(500);
/// Minimum spacing between two full thread dumps during one stall.
const DUMP_MIN_GAP: Duration = Duration::from_secs(60);
/// Thresholds for the "far outside normal" findings.
const MANY_D_STATE_THREADS: usize = 4;
const MANY_ALIVE_TASKS: usize = 20_000;
const DEEP_GLOBAL_QUEUE: usize = 1_000;
const MANY_BLOCKING_THREADS: usize = 400;

const WORKER_PREFIX: &str = "rt-worker-";
const BLOCKING_PREFIX: &str = "rt-blocking-";

static THREAD_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Thread-name generator for `tokio::runtime::Builder::thread_name_fn`.
///
/// The first `worker_threads` runtime threads are the scheduler workers and
/// get `rt-worker-NN`; every later one is a blocking-pool thread and gets
/// `rt-blocking-NN`. Names are capped at 15 bytes by the kernel, which keeps
/// the prefix intact either way.
pub fn thread_namer(worker_threads: usize) -> impl Fn() -> String + Send + Sync + 'static {
    move || {
        let n = THREAD_SEQ.fetch_add(1, Ordering::Relaxed);
        if n < worker_threads {
            format!("{WORKER_PREFIX}{n:02}")
        } else {
            format!("{BLOCKING_PREFIX}{:02}", n - worker_threads)
        }
    }
}

/// Start the monitor thread. `STORAGE_MONITOR_SECS=0` disables it.
pub fn start(handle: Handle) {
    let interval = interval_from_env();
    if interval.is_zero() {
        eprintln!(
            "ts={} level=info event=monitor_disabled",
            logging::format_log_timestamp(SystemTime::now())
        );
        return;
    }
    if let Err(e) = std::thread::Builder::new()
        .name("stall-monitor".to_string())
        .spawn(move || run(handle, interval))
    {
        eprintln!(
            "ts={} level=error event=monitor_failed error={}",
            logging::format_log_timestamp(SystemTime::now()),
            logging::logfmt_string(&e.to_string())
        );
    }
}

fn interval_from_env() -> Duration {
    match std::env::var(ENV_INTERVAL) {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => {
                eprintln!(
                    "ts={} level=warn event=monitor_bad_interval value={} default={}",
                    logging::format_log_timestamp(SystemTime::now()),
                    logging::logfmt_string(&v),
                    DEFAULT_INTERVAL_SECS
                );
                Duration::from_secs(DEFAULT_INTERVAL_SECS)
            }
        },
        Err(_) => Duration::from_secs(DEFAULT_INTERVAL_SECS),
    }
}

fn now() -> String {
    logging::format_log_timestamp(SystemTime::now())
}

/// Per-worker scheduler counters from the previous tick.
struct WorkerCounters {
    parks: Vec<u64>,
    busy: Vec<Duration>,
}

impl WorkerCounters {
    fn read(handle: &Handle) -> Self {
        let m = handle.metrics();
        let n = m.num_workers();
        WorkerCounters {
            parks: (0..n).map(|w| m.worker_park_count(w)).collect(),
            busy: (0..n).map(|w| m.worker_total_busy_duration(w)).collect(),
        }
    }
}

struct Stall {
    started: Instant,
    last_dump: Option<Instant>,
    ticks: u32,
}

fn run(handle: Handle, interval: Duration) {
    let workers = handle.metrics().num_workers();
    eprintln!(
        "ts={} level=info event=monitor_start interval_secs={} workers={} probe_timeout_secs={}",
        now(),
        interval.as_secs(),
        workers,
        PROBE_TIMEOUT.as_secs()
    );

    let mut prev = WorkerCounters::read(&handle);
    let mut stall: Option<Stall> = None;

    loop {
        std::thread::sleep(interval);

        let probe = probe_runtime(&handle);
        let cur = WorkerCounters::read(&handle);
        let threads = snapshot_threads();
        let report = assess(&threads, &prev, &cur, probe);

        crate::debug_log!(
            "ts={} event=monitor_tick probe_ms={} alive_tasks={} global_queue={} threads={} blocking_threads={} d_state={}",
            now(),
            probe.map(|d| d.as_millis()).unwrap_or(u128::MAX),
            handle.metrics().num_alive_tasks(),
            handle.metrics().global_queue_depth(),
            threads.len(),
            report.blocking_threads,
            report.d_state
        );

        match (probe, stall.as_mut()) {
            (None, None) => {
                stall = Some(Stall {
                    started: Instant::now() - PROBE_TIMEOUT,
                    last_dump: None,
                    ticks: 1,
                });
                eprintln!(
                    "ts={} level=error event=runtime_stall detail=\"probe task did not run within {}s\"",
                    now(),
                    PROBE_TIMEOUT.as_secs()
                );
            }
            (None, Some(s)) => s.ticks += 1,
            (Some(d), Some(s)) => {
                eprintln!(
                    "ts={} level=warn event=runtime_recovered stalled_secs={} ticks={} probe_ms={}",
                    now(),
                    s.started.elapsed().as_secs(),
                    s.ticks,
                    d.as_millis()
                );
                stall = None;
            }
            (Some(_), None) => {}
        }

        let findings = findings(&handle, &report, probe);
        if !findings.is_empty() {
            eprintln!(
                "ts={} level=warn event=monitor_warn probe_ms={} alive_tasks={} global_queue={} d_state={} blocking_threads={} busy_blocking={} {}",
                now(),
                probe.map(|d| d.as_millis()).unwrap_or(u128::MAX),
                handle.metrics().num_alive_tasks(),
                handle.metrics().global_queue_depth(),
                report.d_state,
                report.blocking_threads,
                report.busy_blocking,
                findings.join(" ")
            );
        }

        if let Some(s) = stall.as_mut() {
            let due = s.last_dump.is_none_or(|t| t.elapsed() >= DUMP_MIN_GAP);
            if due {
                dump_threads(&threads, &report);
                s.last_dump = Some(Instant::now());
            }
        }

        prev = cur;
    }
}

/// Spawn a no-op task and measure how long the runtime takes to run it.
/// `None` means it did not run within [`PROBE_TIMEOUT`].
fn probe_runtime(handle: &Handle) -> Option<Duration> {
    let (tx, rx) = mpsc::channel::<()>();
    let started = Instant::now();
    handle.spawn(async move {
        let _ = tx.send(());
    });
    rx.recv_timeout(PROBE_TIMEOUT)
        .ok()
        .map(|_| started.elapsed())
}

#[derive(Debug, Clone)]
struct ThreadInfo {
    tid: u32,
    comm: String,
    state: char,
    syscall: String,
    wchan: String,
}

impl ThreadInfo {
    fn worker_index(&self) -> Option<usize> {
        self.comm.strip_prefix(WORKER_PREFIX)?.parse().ok()
    }

    fn is_blocking_pool(&self) -> bool {
        self.comm.starts_with(BLOCKING_PREFIX)
    }

    /// Parked or waiting for I/O readiness — the normal resting state of a
    /// runtime thread.
    fn is_idle(&self) -> bool {
        is_idle_syscall(&self.syscall)
    }
}

fn is_idle_syscall(syscall: &str) -> bool {
    matches!(
        syscall.split('(').next().unwrap_or(""),
        "futex" | "epoll_wait" | "epoll_pwait" | "epoll_pwait2" | "nanosleep" | "clock_nanosleep"
    )
}

fn read_trim(path: &Path) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Enumerate the threads of this process with their kernel-side status.
fn snapshot_threads() -> Vec<ThreadInfo> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
        return out;
    };
    for entry in dir.flatten() {
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let base = entry.path();
        out.push(ThreadInfo {
            tid,
            comm: read_trim(&base.join("comm")),
            state: parse_stat_state(&read_trim(&base.join("stat"))),
            syscall: describe_syscall(&read_trim(&base.join("syscall"))),
            wchan: read_trim(&base.join("wchan")),
        });
    }
    out.sort_by_key(|t| t.tid);
    out
}

/// The state letter from `/proc/<tid>/stat`; the comm field may contain
/// spaces and parentheses, so scan from the last `)`.
fn parse_stat_state(stat: &str) -> char {
    stat.rfind(')')
        .and_then(|i| stat[i + 1..].trim_start().chars().next())
        .unwrap_or('?')
}

/// Turn a `/proc/<tid>/syscall` line into `name`, `name(fd=N)`, `running` or
/// `user` (blocked outside any syscall, e.g. in a page fault).
fn describe_syscall(raw: &str) -> String {
    let mut fields = raw.split_whitespace();
    let Some(first) = fields.next() else {
        return "unknown".to_string();
    };
    if first == "running" {
        return first.to_string();
    }
    let Ok(nr) = first.parse::<i64>() else {
        return "unknown".to_string();
    };
    if nr < 0 {
        return "user".to_string();
    }
    let name = syscall_name(nr);
    if FD_SYSCALLS.contains(&nr) {
        if let Some(fd) = fields
            .next()
            .and_then(|a| i64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
        {
            return format!("{name}(fd={fd})");
        }
    }
    name.to_string()
}

/// Syscalls whose first argument is a file descriptor worth showing.
const FD_SYSCALLS: &[i64] = &[
    0, 1, 3, 5, 8, 17, 18, 19, 20, 40, 44, 45, 46, 47, 74, 75, 217, 326,
];

/// x86_64 syscall numbers that matter for a storage server; anything else is
/// shown by number.
fn syscall_name(nr: i64) -> String {
    let name = match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        28 => "madvise",
        35 => "nanosleep",
        40 => "sendfile",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        56 => "clone",
        59 => "execve",
        72 => "fcntl",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        78 => "getdents",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        87 => "unlink",
        89 => "readlink",
        137 => "statfs",
        138 => "fstatfs",
        202 => "futex",
        217 => "getdents64",
        230 => "clock_nanosleep",
        232 => "epoll_wait",
        257 => "openat",
        258 => "mkdirat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        281 => "epoll_pwait",
        288 => "accept4",
        316 => "renameat2",
        318 => "getrandom",
        326 => "copy_file_range",
        332 => "statx",
        435 => "clone3",
        441 => "epoll_pwait2",
        _ => return format!("syscall_{nr}"),
    };
    name.to_string()
}

/// What the tick concluded about the threads.
struct Assessment {
    /// Workers that neither parked nor sat idle during the whole interval.
    stuck_workers: Vec<ThreadInfo>,
    d_state: usize,
    blocking_threads: usize,
    busy_blocking: usize,
}

fn assess(
    threads: &[ThreadInfo],
    prev: &WorkerCounters,
    cur: &WorkerCounters,
    probe: Option<Duration>,
) -> Assessment {
    let mut stuck_workers = Vec::new();
    for t in threads {
        let Some(idx) = t.worker_index() else {
            continue;
        };
        if idx >= cur.parks.len() || idx >= prev.parks.len() {
            continue;
        }
        let parked_since_last = cur.parks[idx] != prev.parks[idx];
        let busy_since_last = cur.busy[idx] != prev.busy[idx];
        // A healthy worker either parked at some point during the interval or
        // is idle right now. One that did neither has been inside a single
        // poll for the whole interval: blocked in a syscall, or spinning.
        // While the runtime is stalled every worker qualifies regardless.
        if !t.is_idle() && (!parked_since_last && !busy_since_last || probe.is_none()) {
            stuck_workers.push(t.clone());
        }
    }
    Assessment {
        stuck_workers,
        d_state: threads.iter().filter(|t| t.state == 'D').count(),
        blocking_threads: threads.iter().filter(|t| t.is_blocking_pool()).count(),
        busy_blocking: threads
            .iter()
            .filter(|t| t.is_blocking_pool() && !t.is_idle())
            .count(),
    }
}

fn findings(handle: &Handle, report: &Assessment, probe: Option<Duration>) -> Vec<String> {
    let mut out = Vec::new();
    match probe {
        None => out.push("runtime=stalled".to_string()),
        Some(d) if d > SLOW_PROBE => out.push(format!("slow_probe_ms={}", d.as_millis())),
        _ => {}
    }
    if !report.stuck_workers.is_empty() {
        let list: Vec<String> = report
            .stuck_workers
            .iter()
            .map(|t| format!("{}:{}:{}", t.comm, t.state, t.syscall))
            .collect();
        out.push(format!(
            "stuck_workers={} stuck=\"{}\"",
            list.len(),
            list.join(",")
        ));
    }
    if report.d_state >= MANY_D_STATE_THREADS {
        out.push(format!("many_d_state={}", report.d_state));
    }
    if report.blocking_threads >= MANY_BLOCKING_THREADS {
        out.push(format!("many_blocking_threads={}", report.blocking_threads));
    }
    let m = handle.metrics();
    let alive = m.num_alive_tasks();
    if alive >= MANY_ALIVE_TASKS {
        out.push(format!("many_alive_tasks={alive}"));
    }
    let queue = m.global_queue_depth();
    if queue >= DEEP_GLOBAL_QUEUE {
        out.push(format!("deep_global_queue={queue}"));
    }
    out
}

/// Print every thread that is not resting, with its kernel stack when the
/// kernel lets us read it (`/proc/<tid>/stack` needs CAP_SYS_ADMIN on most
/// kernels, so this often yields nothing inside a container).
fn dump_threads(threads: &[ThreadInfo], report: &Assessment) {
    let ts = now();
    let idle = threads.iter().filter(|t| t.is_idle()).count();
    eprintln!(
        "ts={} level=warn event=monitor_dump threads={} idle={} d_state={} stuck_workers={}",
        ts,
        threads.len(),
        idle,
        report.d_state,
        report.stuck_workers.len()
    );
    for t in threads.iter().filter(|t| !t.is_idle()) {
        let stack = read_trim(
            &Path::new("/proc/self/task")
                .join(t.tid.to_string())
                .join("stack"),
        );
        let stack = stack
            .lines()
            .map(|l| l.trim_start_matches("[<0>] ").trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" < ");
        eprintln!(
            "ts={} level=warn event=monitor_thread tid={} name={} state={} syscall={} wchan={} stack={}",
            ts,
            t.tid,
            logging::logfmt_string(&t.comm),
            t.state,
            logging::logfmt_string(&t.syscall),
            logging::logfmt_string(&t.wchan),
            logging::logfmt_string(&stack)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_state_survives_parenthesised_comm() {
        assert_eq!(parse_stat_state("123 (rt-worker-01) S 1 2 3"), 'S');
        assert_eq!(parse_stat_state("123 (odd (name)) D 1 2 3"), 'D');
        assert_eq!(parse_stat_state(""), '?');
    }

    #[test]
    fn syscall_line_is_described() {
        assert_eq!(describe_syscall("running"), "running");
        assert_eq!(describe_syscall("-1 0x7f 0x7f"), "user");
        assert_eq!(describe_syscall("202 0x1 0x80 0x0"), "futex");
        assert_eq!(describe_syscall("1 0x1 0x7f 0x40"), "write(fd=1)");
        assert_eq!(describe_syscall("257 0xffffff9c 0x7f"), "openat");
        assert_eq!(describe_syscall("9999 0x0"), "syscall_9999");
        assert_eq!(describe_syscall(""), "unknown");
    }

    #[test]
    fn idle_detection_uses_syscall_name() {
        assert!(is_idle_syscall("futex"));
        assert!(is_idle_syscall("epoll_wait"));
        assert!(!is_idle_syscall("openat"));
        assert!(!is_idle_syscall("write(fd=1)"));
        assert!(!is_idle_syscall("running"));
    }

    #[test]
    fn namer_labels_workers_then_blocking_threads() {
        THREAD_SEQ.store(0, Ordering::Relaxed);
        let namer = thread_namer(2);
        assert_eq!(namer(), "rt-worker-00");
        assert_eq!(namer(), "rt-worker-01");
        assert_eq!(namer(), "rt-blocking-00");
        assert!(namer().len() <= 15);
    }

    fn info(comm: &str, syscall: &str) -> ThreadInfo {
        ThreadInfo {
            tid: 1,
            comm: comm.to_string(),
            state: 'S',
            syscall: syscall.to_string(),
            wchan: String::new(),
        }
    }

    #[test]
    fn worker_that_never_parked_and_is_not_idle_is_stuck() {
        let threads = vec![
            info("rt-worker-00", "openat"),
            info("rt-worker-01", "futex"),
            info("rt-worker-02", "running"),
            info("rt-blocking-00", "read(fd=7)"),
        ];
        let prev = WorkerCounters {
            parks: vec![5, 5, 5],
            busy: vec![Duration::from_secs(1); 3],
        };
        let mut cur = WorkerCounters {
            parks: vec![5, 5, 9],
            busy: vec![Duration::from_secs(1); 3],
        };
        let a = assess(&threads, &prev, &cur, Some(Duration::from_millis(1)));
        let names: Vec<&str> = a.stuck_workers.iter().map(|t| t.comm.as_str()).collect();
        assert_eq!(names, vec!["rt-worker-00"]);
        assert_eq!(a.blocking_threads, 1);
        assert_eq!(a.busy_blocking, 1);

        // A stalled runtime flags every non-idle worker, parked or not.
        cur.parks = vec![9, 9, 9];
        let a = assess(&threads, &prev, &cur, None);
        assert_eq!(a.stuck_workers.len(), 2);
    }

    /// With its only worker blocked in a sleep the runtime cannot run the
    /// probe task; once the worker is free again it can.
    #[test]
    fn probe_detects_a_blocked_runtime() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        let handle = rt.handle().clone();
        assert!(probe_runtime(&handle).is_some());

        let hold = PROBE_TIMEOUT + Duration::from_secs(2);
        let blocker = handle.spawn(async move { std::thread::sleep(hold) });
        // Give the worker a moment to pick the blocking task up.
        std::thread::sleep(Duration::from_millis(200));
        assert!(probe_runtime(&handle).is_none());

        rt.block_on(blocker).unwrap();
        assert!(probe_runtime(&handle).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_sees_the_calling_thread() {
        let threads = snapshot_threads();
        assert!(!threads.is_empty());
        assert!(threads
            .iter()
            .any(|t| t.syscall == "running" || t.syscall == "user"));
    }
}
