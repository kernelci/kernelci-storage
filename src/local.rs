// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

use crate::{debug_log, CacheState, ReceivedFile};
use async_trait::async_trait;
use axum::http::{HeaderName, HeaderValue};
use chksum_hash_sha2_512 as sha2_512;
use headers::HeaderMap;
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::io::AsyncReadExt;

pub struct LocalDriver;

impl LocalDriver {
    pub fn new() -> Self {
        LocalDriver
    }
}

#[derive(Deserialize)]
struct LocalConfig {
    storage_path: String,
}

/// Get local storage configuration from config.toml, parsed once and cached:
/// every path lookup needs it, and re-parsing the file per request is pure
/// overhead for a value that cannot change without a restart.
fn get_local_config() -> &'static LocalConfig {
    static CONFIG: OnceLock<LocalConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        // Default to "./storage" if no local config section exists
        let local_cfg = match crate::get_config_table().get("local") {
            Some(local_cfg) => local_cfg,
            None => {
                debug_log!(
                    "No local section in config.toml, using default storage path: ./storage"
                );
                return LocalConfig {
                    storage_path: "./storage".to_string(),
                };
            }
        };

        let storage_path = local_cfg
            .get("storage_path")
            .and_then(|v| v.as_str())
            .unwrap_or("./storage")
            .to_string();

        LocalConfig { storage_path }
    })
}

/// Create directory structure for a file path
fn ensure_directory_exists(file_path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Get full file path in storage directory
fn get_storage_file_path(filename: &str) -> Result<PathBuf, String> {
    let config = get_local_config();
    resolve_storage_file_path(Path::new(&config.storage_path), filename)
}

fn resolve_storage_file_path(storage_path: &Path, filename: &str) -> Result<PathBuf, String> {
    let filename = crate::normalize_storage_path(filename)?;
    let root = storage_path.canonicalize().map_err(|e| e.to_string())?;
    let mut resolved = root.clone();
    for component in Path::new(&filename).components() {
        resolved.push(component);
        match fs::symlink_metadata(&resolved) {
            Ok(_) => {
                resolved = resolved.canonicalize().map_err(|e| e.to_string())?;
                if !resolved.starts_with(&root) {
                    return Err("Path resolves outside storage directory".to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(resolved)
}

/// Get metadata file path for storing headers. Pure path arithmetic: the read
/// path calls this per request, so it must not touch the filesystem. Writers
/// call `ensure_metadata_dir` first.
fn get_metadata_file_path(filename: &str) -> PathBuf {
    let config = get_local_config();
    let metadata_path = Path::new(&config.storage_path).join(".metadata");

    // Generate hash-based filename for metadata
    let hash = sha2_512::default().update(filename.as_bytes()).finalize();
    let digest = hash.digest();
    metadata_path.join(format!("{}.headers", digest.to_hex_lowercase()))
}

/// Create the metadata directory if it is missing. Only needed before writing.
fn ensure_metadata_dir() {
    let config = get_local_config();
    let metadata_path = Path::new(&config.storage_path).join(".metadata");
    if !metadata_path.exists() {
        let _ = fs::create_dir_all(&metadata_path);
    }
}

/// Calculate SHA-512 checksum of file data
#[allow(dead_code)]
fn calculate_checksum(filename: &str, data: &[u8]) {
    let hash = sha2_512::default().update(data).finalize();
    let digest = hash.digest();
    debug_log!("File: {} Checksum: {}", filename, digest.to_hex_lowercase());
}

/// Build metadata sidecar content for a new upload: content-type, owner tag
/// (when known) and the optional configured retention tag, so a future
/// retention cleaner can identify expirable files.
fn build_metadata_content(cont_type: &str, owner_email: Option<String>) -> String {
    let mut metadata_content = format!("content-type:{}\n", cont_type);
    if let Some(email) = owner_email {
        metadata_content.push_str(&format!("tag-owner:{}\n", email));
    }
    if let Some((key, value)) = crate::get_retention_tag() {
        metadata_content.push_str(&format!("tag-{}:{}\n", key, value));
    }
    metadata_content
}

/// Write file to local storage using streaming (new version)
async fn write_file_to_local_streaming(
    filename: String,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    owner_email: Option<String>,
) -> Result<(String, usize), String> {
    fs::create_dir_all(&get_local_config().storage_path).map_err(|e| e.to_string())?;
    let file_path = get_storage_file_path(&filename)?;

    // Ensure directory structure exists
    if let Err(e) = ensure_directory_exists(&file_path) {
        return Err(format!("Failed to create directory structure: {}", e));
    }

    // Write the file with streaming
    let mut file = tokio::fs::File::create(&file_path)
        .await
        .map_err(|e| format!("Failed to create file: {}", e))?;

    let mut buffer = vec![0u8; 10 * 1024 * 1024]; // 10MB buffer
    let mut total_bytes = 0;

    loop {
        match data.read(&mut buffer).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                tokio::io::AsyncWriteExt::write_all(&mut file, &buffer[..n])
                    .await
                    .map_err(|e| format!("Failed to write file: {}", e))?;
                total_bytes += n;
                debug_log!("Written {} bytes to local storage", total_bytes);
            }
            Err(e) => return Err(format!("Failed to read stream: {}", e)),
        }
    }

    // Create and write metadata (headers, owner and retention tags)
    ensure_metadata_dir();
    let metadata_path = get_metadata_file_path(&filename);
    if let Ok(mut metadata_file) = File::create(&metadata_path) {
        let metadata_content = build_metadata_content(&cont_type, owner_email);
        let _ = metadata_file.write_all(metadata_content.as_bytes());
    }

    debug_log!("File written to local storage: {}", file_path.display());
    Ok((filename, total_bytes))
}

/// Write file to local storage (legacy version using Vec<u8>)
#[allow(dead_code)]
fn write_file_to_local(
    filename: String,
    data: Vec<u8>,
    cont_type: String,
    owner_email: Option<String>,
) -> Result<String, String> {
    fs::create_dir_all(&get_local_config().storage_path).map_err(|e| e.to_string())?;
    let file_path = get_storage_file_path(&filename)?;

    // Ensure directory structure exists
    if let Err(e) = ensure_directory_exists(&file_path) {
        return Err(format!("Failed to create directory structure: {}", e));
    }

    // Write the file
    match File::create(&file_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&data) {
                return Err(format!("Failed to write file: {}", e));
            }
            calculate_checksum(&filename, &data);
        }
        Err(e) => {
            return Err(format!("Failed to create file: {}", e));
        }
    }

    // Create and write metadata (headers, owner and retention tags)
    ensure_metadata_dir();
    let metadata_path = get_metadata_file_path(&filename);
    if let Ok(mut metadata_file) = File::create(&metadata_path) {
        let metadata_content = build_metadata_content(&cont_type, owner_email);
        let _ = metadata_file.write_all(metadata_content.as_bytes());
    }

    debug_log!("File written to local storage: {}", file_path.display());
    Ok(filename)
}

/// Read headers from metadata file
fn get_headers_from_metadata_file(filename: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let metadata_path = get_metadata_file_path(filename);

    if let Ok(content) = fs::read_to_string(&metadata_path) {
        for line in content.lines() {
            if let Some((name, value)) = line.split_once(':') {
                if let (Ok(key), Ok(val)) = (
                    HeaderName::from_bytes(name.trim().as_bytes()),
                    HeaderValue::from_str(value.trim()),
                ) {
                    headers.insert(key, val);
                }
            }
        }
    } else {
        // Default content-type if metadata file doesn't exist
        if let Ok(val) = HeaderValue::from_str("application/octet-stream") {
            headers.insert("content-type", val);
        }
    }

    headers
}

/// Get file from local storage.
///
/// Runs on a blocking thread, so it opens the file here and hands the caller a
/// ready handle plus its size: that replaces the exists-check with the open
/// itself (one syscall instead of two) and saves the GET handler a separate
/// stat and open on the async worker threads.
fn get_file_from_local(filename: String) -> ReceivedFile {
    let mut received_file = ReceivedFile::not_found(filename.clone(), CacheState::Cached);
    let file_path = match get_storage_file_path(&filename) {
        Ok(path) => path,
        Err(_) => return received_file,
    };

    let file = match File::open(&file_path) {
        Ok(file) => file,
        Err(_) => {
            debug_log!("File not found in local storage: {}", file_path.display());
            return received_file;
        }
    };
    let size = match file.metadata() {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => {
            debug_log!(
                "Not a regular file in local storage: {}",
                file_path.display()
            );
            return received_file;
        }
        Err(e) => {
            eprintln!("Error reading metadata of {}: {}", file_path.display(), e);
            return received_file;
        }
    };

    // For local storage, we use the same file as both original and cached
    received_file.cached_filename = file_path.to_string_lossy().to_string();
    received_file.headers = get_headers_from_metadata_file(&filename);
    received_file.valid = true;
    received_file.file = Some(file);
    received_file.size = size;

    debug_log!("File found in local storage: {}", file_path.display());
    received_file
}

/// List files in local storage directory
fn list_files_in_local(directory: String) -> Vec<String> {
    let config = get_local_config();
    let storage_path = Path::new(&config.storage_path);
    let search_path = if directory == "/" || directory.is_empty() {
        storage_path.to_path_buf()
    } else {
        storage_path.join(directory.trim_start_matches('/'))
    };

    let mut files = Vec::new();

    fn collect_files_recursive(path: &Path, base_path: &Path, files: &mut Vec<String>) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();

                // Skip metadata directory
                if entry_path
                    .file_name()
                    .is_some_and(|name| name == ".metadata")
                {
                    continue;
                }

                if entry_path.is_file() {
                    // Get relative path from storage root
                    if let Ok(relative_path) = entry_path.strip_prefix(base_path) {
                        files.push(relative_path.to_string_lossy().to_string());
                    }
                } else if entry_path.is_dir() {
                    collect_files_recursive(&entry_path, base_path, files);
                }
            }
        }
    }

    if search_path.exists() && search_path.is_dir() {
        collect_files_recursive(&search_path, storage_path, &mut files);
    }

    files.sort();
    debug_log!("Listed {} files from local storage", files.len());
    files
}

/// Set tags for local storage (stored in metadata)
#[allow(dead_code)]
fn set_tags_for_local_file(
    filename: String,
    user_tags: Vec<(String, String)>,
) -> Result<String, String> {
    ensure_metadata_dir();
    let metadata_path = get_metadata_file_path(&filename);

    // Read existing metadata
    let mut existing_content = String::new();
    if metadata_path.exists() {
        existing_content = fs::read_to_string(&metadata_path)
            .map_err(|e| format!("Failed to read metadata file: {}", e))?;
    }

    // Open metadata file for writing (create if doesn't exist)
    let mut metadata_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&metadata_path)
        .map_err(|e| format!("Failed to open metadata file: {}", e))?;

    // Write existing content first
    metadata_file
        .write_all(existing_content.as_bytes())
        .map_err(|e| format!("Failed to write existing metadata: {}", e))?;

    // Write tags
    for (tag, value) in user_tags {
        let tag_line = format!("tag-{}:{}\n", tag, value);
        metadata_file
            .write_all(tag_line.as_bytes())
            .map_err(|e| format!("Failed to write tag: {}", e))?;
    }

    debug_log!("Tags written to metadata file: {}", metadata_path.display());
    Ok("OK".to_string())
}

/// Implement Driver trait for LocalDriver
#[async_trait]
impl super::Driver for LocalDriver {
    async fn write_file(
        &self,
        filename: String,
        data: Vec<u8>,
        cont_type: String,
        owner_email: Option<String>,
    ) -> String {
        let fname = filename.clone();
        match tokio::task::spawn_blocking(move || {
            write_file_to_local(fname, data, cont_type, owner_email)
        })
        .await
        {
            Ok(Ok(_)) => filename,
            Ok(Err(e)) => {
                eprintln!("Local storage write error: {}", e);
                String::new()
            }
            Err(e) => {
                eprintln!("Local storage write task panicked: {}", e);
                String::new()
            }
        }
    }

    async fn write_file_streaming(
        &self,
        filename: String,
        data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        cont_type: String,
        owner_email: Option<String>,
    ) -> (String, usize) {
        match write_file_to_local_streaming(filename.clone(), data, cont_type, owner_email).await {
            Ok((fname, size)) => (fname, size),
            Err(e) => {
                eprintln!("Local storage streaming write error: {}", e);
                (String::new(), 0)
            }
        }
    }

    async fn get_file(&self, filename: String) -> ReceivedFile {
        tokio::task::spawn_blocking(move || get_file_from_local(filename))
            .await
            .unwrap_or_else(|e| {
                eprintln!("Local storage get_file task panicked: {}", e);
                ReceivedFile::not_found(String::new(), CacheState::Cached)
            })
    }

    async fn tag_file(
        &self,
        filename: String,
        user_tags: Vec<(String, String)>,
    ) -> Result<String, String> {
        tokio::task::spawn_blocking(move || set_tags_for_local_file(filename, user_tags))
            .await
            .unwrap_or_else(|e| Err(format!("Local storage tag_file task panicked: {}", e)))
    }

    async fn list_files(&self, directory: String) -> Vec<String> {
        tokio::task::spawn_blocking(move || list_files_in_local(directory))
            .await
            .unwrap_or_else(|e| {
                eprintln!("Local storage list_files task panicked: {}", e);
                Vec::new()
            })
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn new_directories_keep_their_full_path() {
        let root = tempfile::tempdir_in(".").unwrap();
        let relative = root
            .path()
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap_or(root.path());
        let resolved = resolve_storage_file_path(relative, "new/dir/file.txt").unwrap();
        assert_eq!(
            resolved,
            root.path().canonicalize().unwrap().join("new/dir/file.txt")
        );
        assert!(resolve_storage_file_path(relative, "new/../../outside.txt").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlinks_must_resolve_inside_root() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("file.txt"), "outside").unwrap();
        symlink(outside.path(), root.path().join("outside")).unwrap();
        symlink(
            outside.path().join("file.txt"),
            root.path().join("link.txt"),
        )
        .unwrap();
        assert!(resolve_storage_file_path(root.path(), "outside/new.txt").is_err());
        assert!(resolve_storage_file_path(root.path(), "link.txt").is_err());
        std::fs::create_dir(root.path().join("inside")).unwrap();
        symlink(root.path().join("inside"), root.path().join("alias")).unwrap();
        assert_eq!(
            resolve_storage_file_path(root.path(), "alias/new.txt").unwrap(),
            root.path().join("inside/new.txt")
        );
    }
}
