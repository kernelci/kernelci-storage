use crate::debug_log;
use std::fs;
use std::time::SystemTime;
use tokio::time::Duration;

struct Files {
    file: String,
    last_update: SystemTime,
}

async fn read_filesinfo(cache_dir: String) -> Vec<Files> {
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

fn delete_cache_file(file: String) {
    // Truncate from filename .content, and add .headers, delete both files
    let content_filename = file.clone();
    let headers_filename = file.replace(".content", ".headers");
    debug_log!(
        "Deleting files: {} {}",
        &content_filename,
        &headers_filename
    );
    let res = fs::remove_file(&content_filename);
    match res {
        Ok(_) => {}
        Err(_) => {
            debug_log!("Error deleting file: {}", content_filename);
        }
    }
    let res = fs::remove_file(&headers_filename);
    match res {
        Ok(_) => {}
        Err(_) => {
            debug_log!("Error deleting file: {}", headers_filename);
        }
    }
}

async fn clean_disk(cache_dir: String) {
    let files = read_filesinfo(cache_dir).await;
    let mut oldest_file = Files {
        file: "".to_string(),
        last_update: SystemTime::now(),
    };
    for file in files {
        if file.last_update < oldest_file.last_update {
            oldest_file = file;
        }
    }
    // if file is less than 60 min old, do not delete it
    if oldest_file.last_update.elapsed().unwrap() > Duration::from_secs(60 * 60) {
        delete_cache_file(oldest_file.file);
    } else {
        debug_log!(
            "File is less than 60 min old, skipping: {}, sleeping 60 seconds",
            oldest_file.file
        );
        // sleep 60 seconds
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Cache housekeeping loop
/// This function will check the disk space every and clean with some hysteresis
pub async fn cache_loop(cache_dir: &str) {
    let mut cleaning_on: bool = false;
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

        if cleaning_on {
            clean_disk(cache_dir.to_string()).await;
            // critical mode, sleep only 100ms
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else {
            debug_log!("Free disk space: {}%", free_space);
            // normal mode, sleep 5 minutes between samples
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    }
}
