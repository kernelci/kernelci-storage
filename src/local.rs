// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

use crate::{debug_log, get_config_content, ReceivedFile};
use async_trait::async_trait;
use axum::http::{HeaderName, HeaderValue};
use chksum_hash_sha2_512 as sha2_512;
use headers::HeaderMap;
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use toml::Table;

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

/// Get local storage configuration from config.toml
fn get_local_config() -> LocalConfig {
    let cfg_content = get_config_content();
    let cfg: Table = toml::from_str(&cfg_content).unwrap();

    // Default to "./storage" if no local config section exists
    let default_config = LocalConfig {
        storage_path: "./storage".to_string(),
    };

    let local_cfg = match cfg.get("local") {
        Some(local_cfg) => local_cfg,
        None => {
            debug_log!("No local section in config.toml, using default storage path: ./storage");
            return default_config;
        }
    };

    let storage_path = local_cfg
        .get("storage_path")
        .and_then(|v| v.as_str())
        .unwrap_or("./storage")
        .to_string();

    LocalConfig { storage_path }
}

/// Create directory structure for a file path
fn ensure_directory_exists(file_path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Get full file path in storage directory
fn get_storage_file_path(filename: &str) -> PathBuf {
    let config = get_local_config();
    let storage_path = Path::new(&config.storage_path);
    storage_path.join(filename)
}

/// Get metadata file path for storing headers
fn get_metadata_file_path(filename: &str) -> PathBuf {
    let config = get_local_config();
    let storage_path = Path::new(&config.storage_path);
    let metadata_path = storage_path.join(".metadata");

    // Create metadata directory if it doesn't exist
    if !metadata_path.exists() {
        let _ = fs::create_dir_all(&metadata_path);
    }

    // Generate hash-based filename for metadata
    let hash = sha2_512::default().update(filename.as_bytes()).finalize();
    let digest = hash.digest();
    metadata_path.join(format!("{}.headers", digest.to_hex_lowercase()))
}

/// Calculate SHA-512 checksum of file data
fn calculate_checksum(filename: &str, data: &[u8]) {
    let hash = sha2_512::default().update(data).finalize();
    let digest = hash.digest();
    debug_log!("File: {} Checksum: {}", filename, digest.to_hex_lowercase());
}

/// Write file to local storage using streaming (new version)
async fn write_file_to_local_streaming(
    filename: String,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    owner_email: Option<String>,
) -> Result<(String, usize), String> {
    let file_path = get_storage_file_path(&filename);

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

    // Create and write metadata (headers and owner tag)
    let metadata_path = get_metadata_file_path(&filename);
    if let Ok(mut metadata_file) = File::create(&metadata_path) {
        let mut metadata_content = format!("content-type:{}\n", cont_type);
        if let Some(email) = owner_email {
            metadata_content.push_str(&format!("tag-owner:{}\n", email));
        }
        let _ = metadata_file.write_all(metadata_content.as_bytes());
    }

    debug_log!("File written to local storage: {}", file_path.display());
    Ok((filename, total_bytes))
}

/// Write file to local storage (legacy version using Vec<u8>)
fn write_file_to_local(
    filename: String,
    data: Vec<u8>,
    cont_type: String,
    owner_email: Option<String>,
) -> Result<String, String> {
    let file_path = get_storage_file_path(&filename);

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

    // Create and write metadata (headers and owner tag)
    let metadata_path = get_metadata_file_path(&filename);
    if let Ok(mut metadata_file) = File::create(&metadata_path) {
        let mut metadata_content = format!("content-type:{}\n", cont_type);
        if let Some(email) = owner_email {
            metadata_content.push_str(&format!("tag-owner:{}\n", email));
        }
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

/// Get file from local storage
fn get_file_from_local(filename: String) -> ReceivedFile {
    let file_path = get_storage_file_path(&filename);

    let mut received_file = ReceivedFile {
        original_filename: filename.clone(),
        cached_filename: String::new(),
        headers: HeaderMap::new(),
        valid: false,
    };

    // Check if file exists
    if !file_path.exists() {
        debug_log!("File not found in local storage: {}", file_path.display());
        return received_file;
    }

    // For local storage, we use the same file as both original and cached
    received_file.cached_filename = file_path.to_string_lossy().to_string();
    received_file.headers = get_headers_from_metadata_file(&filename);
    received_file.valid = true;

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
            for entry in entries {
                if let Ok(entry) = entry {
                    let entry_path = entry.path();

                    // Skip metadata directory
                    if entry_path
                        .file_name()
                        .map_or(false, |name| name == ".metadata")
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
    }

    if search_path.exists() && search_path.is_dir() {
        collect_files_recursive(&search_path, storage_path, &mut files);
    }

    files.sort();
    debug_log!("Listed {} files from local storage", files.len());
    files
}

/// Set tags for local storage (stored in metadata)
fn set_tags_for_local_file(
    filename: String,
    user_tags: Vec<(String, String)>,
) -> Result<String, String> {
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
    fn write_file(
        &self,
        filename: String,
        data: Vec<u8>,
        cont_type: String,
        owner_email: Option<String>,
    ) -> String {
        match write_file_to_local(filename.clone(), data, cont_type, owner_email) {
            Ok(_) => filename,
            Err(e) => {
                eprintln!("Local storage write error: {}", e);
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

    fn get_file(&self, filename: String) -> ReceivedFile {
        get_file_from_local(filename)
    }

    fn tag_file(
        &self,
        filename: String,
        user_tags: Vec<(String, String)>,
    ) -> Result<String, String> {
        set_tags_for_local_file(filename, user_tags)
    }

    fn list_files(&self, directory: String) -> Vec<String> {
        list_files_in_local(directory)
    }
}
