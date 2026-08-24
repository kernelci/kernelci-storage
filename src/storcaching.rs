use crate::get_config_content;
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::thread;
use std::time::{Instant as StdInstant, SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, Instant};
use toml::Table;

const MAX_CACHE_FILES: usize = 1_000_000;
const DEFAULT_CLEANUP_CHUNK: usize = 100_000;
const DISK_SPACE_LOW_PERCENT: u64 = 12;
const DISK_SPACE_RECOVER_PERCENT: u64 = 13;
const HOUSEKEEPING_INTERVAL_SECS: u64 = 300;

/// How long to wait between two full recounts of the cache.
const CACHE_RECOUNT_INTERVAL_SECS: u64 = 3600;

/// Share of wall-clock time the recount walk may spend actually reading cache
/// directories; it sleeps for the rest.
///
/// The walk competes for the same disk as the request path, and it has no
/// deadline of its own, so it yields instead of saturating the queue. Cold, a
/// full walk is tens of seconds of solid random reads against the data disk,
/// and while it runs every request that touches the cache queues behind it --
/// long enough to time out the uptime probe. Paced, the same walk is spread
/// over several minutes and leaves most of the disk to the request path.
const RECOUNT_DUTY_CYCLE_PERCENT: u32 = 20;

/// Longest the recount sleeps in one go, so a pathologically slow shard cannot
/// stretch a single pause without bound.
const RECOUNT_MAX_SLEEP: Duration = Duration::from_secs(5);

/// Number of `.content` entries currently in the cache.
///
/// Kept up to date incrementally by the download path and by the deletion
/// helpers below, so the housekeeping loop can check the cache size without
/// touching the filesystem. It is only an estimate between recounts:
/// concurrent downloads of the same object, or files removed behind our back,
/// make it drift, and `recount_cache_files` resets it periodically.
static CACHED_FILES: AtomicUsize = AtomicUsize::new(0);

/// Record that a new `.content` entry was published into the cache.
pub fn note_cache_file_added() {
    CACHED_FILES.fetch_add(1, AtomicOrdering::Relaxed);
}

/// Record that a `.content` entry was removed from the cache.
pub fn note_cache_file_removed() {
    let _ = CACHED_FILES.fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |count| {
        Some(count.saturating_sub(1))
    });
}

/// Current number of cached objects, for the housekeeping limits and metrics.
pub fn cached_file_count() -> usize {
    CACHED_FILES.load(AtomicOrdering::Relaxed)
}

/// Length of the hex prefix used as the shard subdirectory name. One level of
/// 256 buckets keeps each shard small even at the MAX_CACHE_FILES cap
/// (~3.9k object pairs per shard), which is plenty for fast directory scans.
const SHARD_PREFIX_LEN: usize = 2;

/// Shard subdirectory name for a cache key (a lowercase hex digest).
fn shard_name(hex: &str) -> &str {
    let len = SHARD_PREFIX_LEN.min(hex.len());
    &hex[..len]
}

/// Build the (content, headers) paths for a cache key under the sharded layout.
pub fn cache_file_paths(cache_dir: &str, hex: &str) -> (PathBuf, PathBuf) {
    let dir = Path::new(cache_dir).join(shard_name(hex));
    (
        dir.join(format!("{}.content", hex)),
        dir.join(format!("{}.headers", hex)),
    )
}

/// Ensure the shard subdirectory for a cache key exists before writing into it.
pub fn ensure_shard_dir(cache_dir: &str, hex: &str) -> std::io::Result<()> {
    fs::create_dir_all(Path::new(cache_dir).join(shard_name(hex)))
}

/// Visit every file path in the cache: shard subdirectories (one level deep)
/// plus any legacy files still sitting directly in the cache root. This keeps
/// the maintenance tasks working during and after migration.
///
/// This is a `read_dir` walk only; it never calls `metadata()`, so it costs one
/// directory read per shard rather than one inode read per cache entry. Callers
/// that need file metadata pay for it themselves, on the entries they care
/// about. Paths are handed to the callback instead of being collected, so a
/// full walk does not have to materialise a vector of ~1M paths.
fn visit_cache_files<F: FnMut(PathBuf)>(cache_dir: &str, visit: F) {
    visit_cache_files_paced(cache_dir, visit, || {})
}

/// `visit_cache_files`, plus a hook that runs after each shard directory has
/// been read. Callers that must not monopolise the disk throttle themselves
/// there; a shard is the natural granularity, being one `read_dir` worth of
/// work.
fn visit_cache_files_paced<F, P>(cache_dir: &str, mut visit: F, mut at_shard_boundary: P)
where
    F: FnMut(PathBuf),
    P: FnMut(),
{
    let entries = match fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Error reading cache directory ({}): {}", cache_dir, e);
            return;
        }
    };

    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            // Descend one level into shard subdirectories.
            if let Ok(sub_entries) = fs::read_dir(entry.path()) {
                for sub_entry in sub_entries.flatten() {
                    visit(sub_entry.path());
                }
            }
            at_shard_boundary();
        } else {
            visit(entry.path());
        }
    }
}

/// Throttles a maintenance walk to `RECOUNT_DUTY_CYCLE_PERCENT` of wall clock.
///
/// Self-tuning: the pause is proportional to the time the preceding burst of
/// work actually took, so a warm walk whose directories are all in the dentry
/// cache barely pauses at all, while a cold one that is hitting the disk for
/// every entry backs off hard. Nothing has to know in advance which it is.
struct Pacer {
    burst_started: StdInstant,
}

impl Pacer {
    fn new() -> Self {
        Self {
            burst_started: StdInstant::now(),
        }
    }

    /// Sleep long enough that the work done since the last pause stays within
    /// the duty cycle. Called from a blocking context, never a tokio worker.
    fn pause(&mut self) {
        thread::sleep(pause_after(self.burst_started.elapsed()));
        self.burst_started = StdInstant::now();
    }
}

/// How long to sleep after a burst of work that took `worked`, to hold the
/// walk to `RECOUNT_DUTY_CYCLE_PERCENT` of wall clock.
fn pause_after(worked: Duration) -> Duration {
    let pause =
        worked.saturating_mul(100 - RECOUNT_DUTY_CYCLE_PERCENT) / RECOUNT_DUTY_CYCLE_PERCENT;
    pause.min(RECOUNT_MAX_SLEEP)
}

/// Is this a cache content entry (as opposed to a `.headers` sidecar or a
/// `.part` file belonging to an in-flight download)?
fn is_content_file(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "content")
}

/// Count the cache entries with a `read_dir`-only walk and reset the counter to
/// the result.
///
/// Cheaper than the per-entry `metadata()` walk in `scan_cache_directory`, but
/// not cheap: ~1M directory entries across the shards, which is minutes of
/// random reads once the dentry cache has been reclaimed. It is therefore
/// paced, and must only be called from a blocking context.
fn recount_cache_files(cache_dir: &str) -> usize {
    let mut total = 0;
    let mut pacer = Pacer::new();
    visit_cache_files_paced(
        cache_dir,
        |path| {
            if is_content_file(&path) {
                total += 1;
            }
        },
        || pacer.pause(),
    );
    CACHED_FILES.store(total, AtomicOrdering::Relaxed);
    total
}

/// Migrate a legacy flat cache layout (`cache/<hash>.content`) into the
/// one-level sharded layout (`cache/<ab>/<hash>.content`). Idempotent: files
/// already inside shard subdirectories are skipped, so it is cheap to run on
/// every startup once migration has completed.
pub fn migrate_cache_layout(cache_dir: &str) {
    let entries = match fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Cache migration: cannot read {}: {}", cache_dir, e);
            return;
        }
    };

    let mut moved: u64 = 0;
    let mut failed: u64 = 0;

    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            continue; // already a shard directory
        }

        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        if !(name.ends_with(".content") || name.ends_with(".headers")) {
            continue;
        }

        // The filename starts with the hex digest; its first bytes form the shard.
        if name.len() < SHARD_PREFIX_LEN
            || !name.as_bytes()[..SHARD_PREFIX_LEN]
                .iter()
                .all(u8::is_ascii_hexdigit)
        {
            continue;
        }

        let shard_dir = Path::new(cache_dir).join(&name[..SHARD_PREFIX_LEN]);
        if let Err(e) = fs::create_dir_all(&shard_dir) {
            debug_log!("Cache migration: cannot create {:?}: {}", shard_dir, e);
            failed += 1;
            continue;
        }

        let target = shard_dir.join(&name);
        match fs::rename(&path, &target) {
            Ok(_) => moved += 1,
            Err(e) => {
                debug_log!("Cache migration: failed to move {:?}: {}", path, e);
                failed += 1;
            }
        }
    }

    if moved > 0 || failed > 0 {
        println!(
            "[cache-migration] moved {} legacy cache files into sharded layout ({} failures).",
            moved, failed
        );
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct CacheConfig {
    #[serde(default = "default_cleanup_chunk_size")]
    cleanup_chunk_size: usize,
}

fn default_cleanup_chunk_size() -> usize {
    DEFAULT_CLEANUP_CHUNK
}

fn get_cache_config() -> CacheConfig {
    let cfg_content = get_config_content();
    let cfg: Table = toml::from_str(cfg_content).unwrap_or_else(|_| Table::new());
    let cleanup_chunk_size = cfg
        .get("cache")
        .and_then(|section| section.get("cleanup_chunk_size"))
        .and_then(|value| value.as_integer())
        .map(|v| v.max(1) as usize)
        .unwrap_or(DEFAULT_CLEANUP_CHUNK);
    CacheConfig { cleanup_chunk_size }
}

#[derive(Clone)]
struct CacheFile {
    file: String,
    last_update: SystemTime,
}

impl CacheFile {
    fn modified_duration(&self) -> Duration {
        self.last_update
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
    }
}

impl PartialEq for CacheFile {
    fn eq(&self, other: &Self) -> bool {
        self.modified_duration() == other.modified_duration()
    }
}

impl Eq for CacheFile {}

impl PartialOrd for CacheFile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CacheFile {
    fn cmp(&self, other: &Self) -> Ordering {
        self.modified_duration().cmp(&other.modified_duration())
    }
}

#[derive(Default)]
struct CacheScanResult {
    total_files: usize,
    oldest_files: Vec<CacheFile>,
}

#[derive(Default)]
struct CleanOutcome {
    deleted_entries: u64,
    reclaimed_bytes: u64,
}

/// Walk the cache and pick the `chunk_size` least recently modified entries.
///
/// This calls `metadata()` once per cache entry, which on a large cache means
/// hundreds of thousands of inode reads and minutes of disk time when they are
/// not in the page cache. It must only be called when eviction is actually
/// about to happen, and only from a blocking context.
fn scan_cache_directory(cache_dir: &str, chunk_size: usize) -> CacheScanResult {
    let mut result = CacheScanResult::default();

    let mut heap = if chunk_size > 0 {
        Some(BinaryHeap::with_capacity(chunk_size.saturating_add(1)))
    } else {
        None
    };

    visit_cache_files(cache_dir, |path| {
        if !is_content_file(&path) {
            return;
        }
        let file = match path.to_str() {
            Some(path_str) => path_str.to_string(),
            None => return,
        };

        result.total_files += 1;

        if let Some(heap) = heap.as_mut() {
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => return,
            };
            let last_update = match metadata.modified() {
                Ok(last_update) => last_update,
                Err(_) => return,
            };
            heap.push(CacheFile { file, last_update });
            if heap.len() > chunk_size {
                heap.pop();
            }
        }
    });

    if let Some(heap) = heap {
        let mut oldest_files = heap.into_sorted_vec();
        oldest_files.truncate(chunk_size);
        result.oldest_files = oldest_files;
    }

    // The walk just produced an exact count, so take the opportunity to drop
    // any drift the incremental counter accumulated.
    CACHED_FILES.store(result.total_files, AtomicOrdering::Relaxed);

    result
}

fn freediskspace_percent(cache_dir: &str) -> u64 {
    let total_r = fs2::total_space(cache_dir);
    let free_r = fs2::available_space(cache_dir);
    let total = match total_r {
        Ok(total) => total as f64,
        Err(_) => {
            eprintln!("Error getting disk total space");
            return 0;
        }
    };
    let free = match free_r {
        Ok(free) => free as f64,
        Err(_) => {
            eprintln!("Error getting disk free space");
            return 0;
        }
    };

    let percent = (free / total) * 100.0;
    percent as u64
}

fn delete_cache_file(file: &str) -> CleanOutcome {
    // Truncate from filename .content, and add .headers, delete both files
    let content_filename = file.to_string();
    let headers_filename = file.replace(".content", ".headers");
    debug_log!(
        "Deleting files: {} {}",
        &content_filename,
        &headers_filename
    );
    let mut outcome = CleanOutcome::default();
    let content_size = fs::metadata(&content_filename)
        .map(|m| m.len())
        .unwrap_or(0);
    let header_size = fs::metadata(&headers_filename)
        .map(|m| m.len())
        .unwrap_or(0);
    match fs::remove_file(&content_filename) {
        Ok(_) => {
            outcome.deleted_entries = 1;
            outcome.reclaimed_bytes += content_size;
            note_cache_file_removed();
        }
        Err(_) => {
            debug_log!("Error deleting file: {}", content_filename);
        }
    }
    match fs::remove_file(&headers_filename) {
        Ok(_) => {
            outcome.reclaimed_bytes += header_size;
        }
        Err(_) => {
            debug_log!("Error deleting file: {}", headers_filename);
        }
    }
    outcome
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    if bytes >= TB as u64 {
        format!("{:.1}TB", bytes as f64 / TB)
    } else if bytes >= GB as u64 {
        format!("{:.1}GB", bytes as f64 / GB)
    } else if bytes >= MB as u64 {
        format!("{:.1}MB", bytes as f64 / MB)
    } else if bytes >= KB as u64 {
        format!("{:.1}KB", bytes as f64 / KB)
    } else {
        format!("{}B", bytes)
    }
}

fn enforce_cache_file_limit(cache_dir: &str, chunk_size: usize) -> (CleanOutcome, usize) {
    let mut outcome = CleanOutcome::default();

    loop {
        let scan = scan_cache_directory(cache_dir, chunk_size);
        if scan.total_files <= MAX_CACHE_FILES {
            return (outcome, scan.total_files);
        }

        if scan.oldest_files.is_empty() {
            debug_log!(
                "Cache file limit exceeded ({} items) but no deletable files were found",
                scan.total_files
            );
            return (outcome, scan.total_files);
        }

        let mut deleted_any = false;
        for entry in &scan.oldest_files {
            let res = delete_cache_file(&entry.file);
            if res.deleted_entries > 0 {
                deleted_any = true;
            }
            outcome.deleted_entries += res.deleted_entries;
            outcome.reclaimed_bytes += res.reclaimed_bytes;
        }

        if !deleted_any {
            debug_log!("Cache file limit cleanup could not delete any files, stopping iteration");
            return (outcome, scan.total_files);
        }
    }
}

struct DiskCleanupResult {
    outcome: CleanOutcome,
    final_free_space: u64,
}

fn enforce_disk_space(
    cache_dir: &str,
    chunk_size: usize,
    mut free_space: u64,
) -> DiskCleanupResult {
    let mut outcome = CleanOutcome::default();

    while free_space < DISK_SPACE_LOW_PERCENT {
        let scan = scan_cache_directory(cache_dir, chunk_size);
        if scan.oldest_files.is_empty() {
            debug_log!(
                "Disk space is low ({}%), but no cache files are available for removal",
                free_space
            );
            break;
        }

        let mut deleted_any = false;
        for entry in &scan.oldest_files {
            let res = delete_cache_file(&entry.file);
            if res.deleted_entries > 0 {
                deleted_any = true;
            }
            outcome.deleted_entries += res.deleted_entries;
            outcome.reclaimed_bytes += res.reclaimed_bytes;
        }

        if !deleted_any {
            debug_log!("Failed to delete files during disk cleanup, aborting");
            break;
        }

        free_space = freediskspace_percent(cache_dir);
        if free_space >= DISK_SPACE_RECOVER_PERCENT {
            break;
        }
    }

    DiskCleanupResult {
        outcome,
        final_free_space: free_space,
    }
}

fn log_housekeeping(
    free_space: u64,
    files_in_cache: usize,
    deleted_entries: u64,
    reclaimed_bytes: u64,
) {
    if deleted_entries > 0 {
        println!(
            "[housekeeping] {}% disk space remaining, {} files in cache, deleted {} {} and recovered {} space.",
            free_space,
            files_in_cache,
            deleted_entries,
            if deleted_entries == 1 { "file" } else { "files" },
            format_bytes(reclaimed_bytes)
        );
    } else {
        println!(
            "[housekeeping] {}% disk space remaining, {} files in cache. No action taken.",
            free_space, files_in_cache
        );
    }
}

/// Run a blocking cache maintenance step off the async runtime.
///
/// Everything in this module is synchronous filesystem work. Running it
/// directly in the housekeeping task would block a tokio worker thread for as
/// long as the walk takes, which on a large cache is minutes.
async fn blocking<T, F>(what: &str, work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => Some(result),
        Err(e) => {
            eprintln!("Cache housekeeping task ({}) failed: {}", what, e);
            None
        }
    }
}

/// Cache housekeeping loop
/// Enforces cache size limits and disk space thresholds with periodic logging
///
/// The per-tick work is deliberately cheap: a `statvfs` for the free space plus
/// an in-memory counter for the cache size. The expensive walks only run when a
/// limit is actually crossed.
///
/// Re-anchoring that counter is `recount_loop`'s job, on its own schedule. It
/// used to run here, every twelfth tick, which meant a slow walk also held up
/// the free-space check -- the one piece of housekeeping that has to stay
/// responsive, since it is what keeps the disk from filling.
pub async fn cache_loop(cache_dir: &str) {
    let config = get_cache_config();
    let cleanup_chunk_size = config.cleanup_chunk_size.max(1);
    let mut deleted_entries_counter: u64 = 0;
    let mut reclaimed_bytes_counter: u64 = 0;
    let mut next_log = Instant::now();

    loop {
        if cached_file_count() > MAX_CACHE_FILES {
            let dir = cache_dir.to_string();
            if let Some((limit_outcome, total_files)) = blocking("file limit", move || {
                enforce_cache_file_limit(&dir, cleanup_chunk_size)
            })
            .await
            {
                println!(
                    "Cache file limit exceeded ({} entries), evicted {} entries.",
                    total_files, limit_outcome.deleted_entries
                );
                deleted_entries_counter += limit_outcome.deleted_entries;
                reclaimed_bytes_counter += limit_outcome.reclaimed_bytes;
            }
        }

        // Read after the file-limit pass, so eviction there is reflected here.
        let dir = cache_dir.to_string();
        let mut free_space = blocking("free space", move || freediskspace_percent(&dir))
            .await
            .unwrap_or(0);

        if free_space < DISK_SPACE_LOW_PERCENT {
            println!(
                "Free disk is LOW: {}%, starting cache eviction.",
                free_space
            );
            let dir = cache_dir.to_string();
            if let Some(disk_result) = blocking("disk space", move || {
                enforce_disk_space(&dir, cleanup_chunk_size, free_space)
            })
            .await
            {
                deleted_entries_counter += disk_result.outcome.deleted_entries;
                reclaimed_bytes_counter += disk_result.outcome.reclaimed_bytes;
                free_space = disk_result.final_free_space;
                if free_space >= DISK_SPACE_RECOVER_PERCENT {
                    println!("Free disk space is OK: {}%, stopping eviction.", free_space);
                }
            }
        } else {
            debug_log!("Free disk space: {}%", free_space);
        }

        if Instant::now() >= next_log {
            log_housekeeping(
                free_space,
                cached_file_count(),
                deleted_entries_counter,
                reclaimed_bytes_counter,
            );
            deleted_entries_counter = 0;
            reclaimed_bytes_counter = 0;
            next_log = Instant::now() + Duration::from_secs(HOUSEKEEPING_INTERVAL_SECS);
        }

        tokio::time::sleep(Duration::from_secs(HOUSEKEEPING_INTERVAL_SECS)).await;
    }
}

/// Periodically re-anchor the cached-file counter against the filesystem.
///
/// The counter is maintained incrementally by the download and deletion paths,
/// so it drifts: racing downloads of the same object double-count, and files
/// removed behind our back are never subtracted. Nothing here is urgent -- the
/// counter guards a 1M-entry cap that a drift of a few thousand cannot hide --
/// so the walk is paced and runs well away from the housekeeping loop.
pub async fn recount_loop(cache_dir: &str) {
    loop {
        let dir = cache_dir.to_string();
        if let Some(total) = blocking("recount", move || recount_cache_files(&dir)).await {
            debug_log!("Cache recount: {} entries", total);
        }
        tokio::time::sleep(Duration::from_secs(CACHE_RECOUNT_INTERVAL_SECS)).await;
    }
}

fn remove_zero_sized_files(cache_dir: &str) -> u64 {
    let mut removed = 0;

    visit_cache_files(cache_dir, |path| {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => return,
        };

        if !metadata.is_file() || metadata.len() != 0 {
            return;
        }

        if let Err(e) = fs::remove_file(&path) {
            debug_log!("Failed to remove zero-sized file {:?}: {}", path, e);
        } else {
            removed += 1;
            if is_content_file(&path) {
                note_cache_file_removed();
            }
        }
    });

    removed
}

fn remove_orphan_files(cache_dir: &str) -> u64 {
    let mut contents = HashSet::new();
    let mut headers = HashSet::new();

    visit_cache_files(cache_dir, |path| {
        let path = match path.to_str() {
            Some(path) => path.to_string(),
            None => return,
        };

        if let Some(base) = path.strip_suffix(".content") {
            contents.insert(base.to_string());
        } else if let Some(base) = path.strip_suffix(".headers") {
            headers.insert(base.to_string());
        }
    });

    let mut removed = 0;

    for base in contents.difference(&headers) {
        let file = format!("{}.content", base);
        if let Err(e) = fs::remove_file(&file) {
            debug_log!("Failed to remove orphan content {}: {}", file, e);
        } else {
            removed += 1;
            note_cache_file_removed();
        }
    }

    for base in headers.difference(&contents) {
        let file = format!("{}.headers", base);
        if let Err(e) = fs::remove_file(&file) {
            debug_log!("Failed to remove orphan headers {}: {}", file, e);
        } else {
            removed += 1;
        }
    }

    removed
}

fn run_cache_validation(cache_dir: String) {
    let zero_removed = remove_zero_sized_files(&cache_dir);
    let orphan_removed = remove_orphan_files(&cache_dir);

    println!(
        "[cache-validation] removed {} zero-sized files and {} orphaned cache entries.",
        zero_removed, orphan_removed
    );
}

pub async fn validate_cache(cache_dir: String) {
    if let Err(e) = tokio::task::spawn_blocking(move || run_cache_validation(cache_dir)).await {
        eprintln!("Cache validation task failed: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, b"x").unwrap();
    }

    /// The whole module shares one process-wide counter, so this stays a single
    /// test rather than several that would race each other.
    #[test]
    fn cache_file_counter_tracks_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let cache_dir = root.to_str().unwrap();

        // Sharded entries, a legacy entry still in the cache root, plus the
        // sidecars and in-flight downloads that must not be counted.
        touch(&root.join("ab/abcd.content"));
        touch(&root.join("ab/abcd.headers"));
        touch(&root.join("cd/cdef.content"));
        touch(&root.join("cd/cdef.headers"));
        touch(&root.join("legacy.content"));
        touch(&root.join("legacy.headers"));
        touch(&root.join("ef/efgh.content.1234.part"));

        assert_eq!(recount_cache_files(cache_dir), 3);
        assert_eq!(cached_file_count(), 3);

        // The download path keeps the counter current without a walk.
        note_cache_file_added();
        assert_eq!(cached_file_count(), 4);

        // Deleting an entry removes both files and decrements once.
        let evicted = root.join("ab/abcd.content");
        let outcome = delete_cache_file(evicted.to_str().unwrap());
        assert_eq!(outcome.deleted_entries, 1);
        assert!(!evicted.exists());
        assert!(!root.join("ab/abcd.headers").exists());
        assert_eq!(cached_file_count(), 3);

        // A recount re-anchors the counter after the drift introduced above.
        assert_eq!(recount_cache_files(cache_dir), 2);

        // The counter never wraps below zero, however far it drifts.
        for _ in 0..5 {
            note_cache_file_removed();
        }
        assert_eq!(cached_file_count(), 0);

        // The expensive walk agrees with the cheap one, and re-anchors too.
        let scan = scan_cache_directory(cache_dir, 10);
        assert_eq!(scan.total_files, 2);
        assert_eq!(scan.oldest_files.len(), 2);
        assert_eq!(cached_file_count(), 2);
    }

    #[test]
    fn recount_pauses_in_proportion_to_the_work_it_did() {
        // A warm shard costs almost nothing, so the pause is negligible too.
        assert_eq!(
            pause_after(Duration::from_millis(4)),
            Duration::from_millis(16)
        );

        // A cold one backs off to the configured duty cycle: four parts idle
        // for every one part reading.
        assert_eq!(pause_after(Duration::from_secs(1)), Duration::from_secs(4));

        // However slow a single shard gets, one pause stays bounded.
        assert_eq!(pause_after(Duration::from_secs(600)), RECOUNT_MAX_SLEEP);

        assert_eq!(pause_after(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn paced_walk_visits_every_entry_and_pauses_once_per_shard() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        touch(&root.join("ab/one.content"));
        touch(&root.join("ab/two.content"));
        touch(&root.join("cd/three.content"));
        touch(&root.join("legacy.content"));

        let mut seen = Vec::new();
        let mut shards = 0;
        visit_cache_files_paced(
            root.to_str().unwrap(),
            |path| seen.push(path.file_name().unwrap().to_str().unwrap().to_string()),
            || shards += 1,
        );

        seen.sort();
        assert_eq!(
            seen,
            [
                "legacy.content",
                "one.content",
                "three.content",
                "two.content"
            ]
        );
        // Once per shard directory, and not for the legacy file in the root.
        assert_eq!(shards, 2);
    }
}
