use crate::debug_log;
use std::fs;
use std::time::SystemTime;
use tokio::time::{Duration, Instant};

struct Files {
    file: String,
    last_update: SystemTime,
}

#[derive(Default)]
struct CleanOutcome {
    deleted_entries: u64,
    reclaimed_bytes: u64,
}

async fn read_filesinfo(cache_dir: &str) -> Vec<Files> {
    let mut files = Vec::new();
    let paths = fs::read_dir(&cache_dir);
    match paths {
        Ok(paths) => {
            for path in paths {
                let path = path.unwrap().path();
                let file = path.to_str().unwrap().to_string();
                let metadata = fs::metadata(&file).unwrap();
                let last_update = metadata.modified().unwrap();
                // is this file ending with ".content"?
                if !file.ends_with(".content") {
                    continue;
                }
                files.push(Files { file, last_update });
            }
            files
        }
        Err(_) => {
            eprintln!("Error reading cache directory files");
            Vec::new()
        }
    }
}

async fn freediskspace_percent(cache_dir: String) -> u64 {
    let total_r = fs2::total_space(&cache_dir);
    let free_r = fs2::available_space(&cache_dir);
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

async fn clean_disk(cache_dir: &str) -> CleanOutcome {
    let files = read_filesinfo(cache_dir).await;
    let mut oldest_file: Option<Files> = None;
    for file in files {
        if oldest_file
            .as_ref()
            .map(|old| file.last_update < old.last_update)
            .unwrap_or(true)
        {
            oldest_file = Some(file);
        }
    }
    if let Some(file) = oldest_file {
        if let Ok(age) = file.last_update.elapsed() {
            if age > Duration::from_secs(60 * 60) {
                return delete_cache_file(&file.file);
            } else {
                debug_log!(
                    "File is less than 60 min old, skipping: {}, sleeping 60 seconds",
                    file.file
                );
                // sleep 60 seconds
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    }
    CleanOutcome::default()
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

async fn log_housekeeping(
    cache_dir: &str,
    free_space: u64,
    deleted_entries: u64,
    reclaimed_bytes: u64,
) {
    let files_in_cache = read_filesinfo(cache_dir).await.len();
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
/// This function will check the disk space every and clean with some hysteresis
pub async fn cache_loop(cache_dir: &str) {
    let mut cleaning_on: bool = false;
    let mut deleted_entries_counter: u64 = 0;
    let mut reclaimed_bytes_counter: u64 = 0;
    let mut next_log = Instant::now();
    loop {
        let free_space = freediskspace_percent(cache_dir.to_string()).await;
        if free_space < 12 && !cleaning_on {
            cleaning_on = true;
            println!("Free disk is LOW: {}%, cleaning is on", free_space);
        }
        if free_space > 13 && cleaning_on {
            cleaning_on = false;
            println!("Free disk space is OK: {}%, cleaning is off", free_space);
        }

        if Instant::now() >= next_log {
            log_housekeeping(
                cache_dir,
                free_space,
                deleted_entries_counter,
                reclaimed_bytes_counter,
            )
            .await;
            deleted_entries_counter = 0;
            reclaimed_bytes_counter = 0;
            next_log = Instant::now() + Duration::from_secs(300);
        }

        if cleaning_on {
            let outcome = clean_disk(cache_dir).await;
            deleted_entries_counter += outcome.deleted_entries;
            reclaimed_bytes_counter += outcome.reclaimed_bytes;
            // critical mode, sleep only 100ms
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else {
            debug_log!("Free disk space: {}%", free_space);
            // normal mode, sleep 5 minutes between samples
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    }
}
