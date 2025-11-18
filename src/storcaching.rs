use crate::{debug_log, get_config_content};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, Instant};
use toml::Table;

const MAX_CACHE_FILES: usize = 1_000_000;
const DEFAULT_CLEANUP_CHUNK: usize = 100_000;
const DISK_SPACE_LOW_PERCENT: u64 = 12;
const DISK_SPACE_RECOVER_PERCENT: u64 = 13;
const HOUSEKEEPING_INTERVAL_SECS: u64 = 300;

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
    let cfg: Table = toml::from_str(&cfg_content).unwrap_or_else(|_| Table::new());
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

fn scan_cache_directory(cache_dir: &str, chunk_size: usize) -> CacheScanResult {
    let mut result = CacheScanResult::default();
    let entries = match fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Error reading cache directory files ({}): {}", cache_dir, e);
            return result;
        }
    };

    let mut heap = if chunk_size > 0 {
        Some(BinaryHeap::with_capacity(chunk_size.saturating_add(1)))
    } else {
        None
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file = match path.to_str() {
            Some(path_str) => path_str.to_string(),
            None => continue,
        };

        if !file.ends_with(".content") {
            continue;
        }

        result.total_files += 1;

        if let Some(heap) = heap.as_mut() {
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let last_update = match metadata.modified() {
                Ok(last_update) => last_update,
                Err(_) => continue,
            };
            heap.push(CacheFile { file, last_update });
            if heap.len() > chunk_size {
                heap.pop();
            }
        }
    }

    if let Some(heap) = heap {
        let mut oldest_files = heap.into_sorted_vec();
        oldest_files.truncate(chunk_size);
        result.oldest_files = oldest_files;
    }

    result
}

async fn freediskspace_percent(cache_dir: &str) -> u64 {
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

async fn enforce_cache_file_limit(cache_dir: &str, chunk_size: usize) -> (CleanOutcome, usize) {
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

async fn enforce_disk_space(
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

        free_space = freediskspace_percent(cache_dir).await;
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

/// Cache housekeeping loop
/// Enforces cache size limits and disk space thresholds with periodic logging
pub async fn cache_loop(cache_dir: &str) {
    let config = get_cache_config();
    let cleanup_chunk_size = config.cleanup_chunk_size.max(1);
    let mut deleted_entries_counter: u64 = 0;
    let mut reclaimed_bytes_counter: u64 = 0;
    let mut cached_file_count: usize = 0;
    let mut next_log = Instant::now();

    loop {
        let (limit_outcome, file_count) =
            enforce_cache_file_limit(cache_dir, cleanup_chunk_size).await;
        deleted_entries_counter += limit_outcome.deleted_entries;
        reclaimed_bytes_counter += limit_outcome.reclaimed_bytes;
        cached_file_count = file_count;

        let mut free_space = freediskspace_percent(cache_dir).await;
        if free_space < DISK_SPACE_LOW_PERCENT {
            println!(
                "Free disk is LOW: {}%, starting cache eviction.",
                free_space
            );
            let disk_result = enforce_disk_space(cache_dir, cleanup_chunk_size, free_space).await;
            deleted_entries_counter += disk_result.outcome.deleted_entries;
            reclaimed_bytes_counter += disk_result.outcome.reclaimed_bytes;
            cached_file_count =
                cached_file_count.saturating_sub(disk_result.outcome.deleted_entries as usize);
            free_space = disk_result.final_free_space;
            if free_space >= DISK_SPACE_RECOVER_PERCENT {
                println!("Free disk space is OK: {}%, stopping eviction.", free_space);
            }
        } else {
            debug_log!("Free disk space: {}%", free_space);
        }

        if Instant::now() >= next_log {
            log_housekeeping(
                free_space,
                cached_file_count,
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

fn remove_zero_sized_files(cache_dir: &str) -> u64 {
    let mut removed = 0;
    let entries = match fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Error reading cache directory during zero-sized cleanup: {}", e);
            return 0;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if !metadata.is_file() || metadata.len() != 0 {
            continue;
        }

        if let Err(e) = fs::remove_file(&path) {
            debug_log!("Failed to remove zero-sized file {:?}: {}", path, e);
        } else {
            removed += 1;
        }
    }

    removed
}

fn remove_orphan_files(cache_dir: &str) -> u64 {
    let entries = match fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Error reading cache directory during orphan cleanup: {}", e);
            return 0;
        }
    };

    let mut contents = HashSet::new();
    let mut headers = HashSet::new();

    for entry in entries.flatten() {
        let path = match entry.path().to_str() {
            Some(path) => path.to_string(),
            None => continue,
        };

        if let Some(base) = path.strip_suffix(".content") {
            contents.insert(base.to_string());
        } else if let Some(base) = path.strip_suffix(".headers") {
            headers.insert(base.to_string());
        }
    }

    let mut removed = 0;

    for base in contents.difference(&headers) {
        let file = format!("{}.content", base);
        if let Err(e) = fs::remove_file(&file) {
            debug_log!("Failed to remove orphan content {}: {}", file, e);
        } else {
            removed += 1;
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
