// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

pub struct AzureDriver;

impl AzureDriver {
    pub fn new() -> Self {
        AzureDriver
    }
}

use crate::{debug_log, get_config_content, ReceivedFile};
use async_trait::async_trait;
use axum::http::{HeaderName, HeaderValue};
use azure_storage::StorageCredentials;
use azure_storage_blobs::container::operations::BlobItem;
use azure_storage_blobs::prelude::{
    BlobBlockType, BlobClient, BlockId, BlockList, ClientBuilder, ContainerClient, Tags,
};
use chksum_hash_sha2_512 as sha2_512;
use futures::stream::StreamExt;
use headers::HeaderMap;
use reqwest::Client;
use serde::Deserialize;
use std::fs::read_to_string;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::sync::OnceLock;
use tempfile::Builder;
use tokio::io::AsyncReadExt;
use toml::Table;

#[derive(Deserialize)]
struct AzureConfig {
    account: String,
    key: String,
    container: String,
    sastoken: String,
}

// Sanitize Azure Blob Index tag key/value components.
// Replace any non [A-Za-z0-9_.-] characters with '_'.
fn sanitize_tag_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn normalize_sas_token(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with('?') {
        trimmed.to_string()
    } else {
        format!("?{}", trimmed)
    }
}

/// Get Azure credentials from config.toml
fn get_azure_credentials(name: &str) -> AzureConfig {
    let cfg_content = get_config_content();
    let cfg: Table = toml::from_str(&cfg_content).unwrap();
    let azure_cfg = cfg.get(name).unwrap();
    let account = azure_cfg.get("account").unwrap().as_str().unwrap();
    let key = azure_cfg.get("key").unwrap().as_str().unwrap();
    let container = azure_cfg.get("container").unwrap().as_str().unwrap();
    let sastoken = azure_cfg.get("sastoken").unwrap().as_str().unwrap();
    //println!("Azure account: {} key: {} sastoken: {} container: {}", account, key, sastoken, container);
    AzureConfig {
        account: account.to_string(),
        key: key.to_string(),
        container: container.to_string(),
        sastoken: normalize_sas_token(sastoken),
    }
}

/// Shared container client so every blob operation reuses one HTTP
/// connection pool. Building a ClientBuilder per operation creates a fresh
/// HTTP client each time, which costs a TCP+TLS handshake per request and
/// dominates latency when uploading many small files.
fn azure_container_client() -> &'static ContainerClient {
    static CLIENT: OnceLock<ContainerClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let cfg = get_azure_credentials("azure");
        let credential = StorageCredentials::access_key(cfg.account.as_str(), cfg.key.clone());
        ClientBuilder::new(cfg.account.clone(), credential).container_client(cfg.container.clone())
    })
}

fn azure_blob_client(blob: &str) -> BlobClient {
    azure_container_client().blob_client(blob)
}

/// Shared client for plain HTTP downloads (SAS URL fetches), pooled for the
/// same reason as azure_container_client.
fn http_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(Client::new)
}

#[allow(dead_code)]
fn calculate_checksum(filename: &String, data: &[u8]) {
    let hash = sha2_512::default().update(data).finalize();
    let digest = hash.digest();
    debug_log!("File: {} Checksum: {}", filename, digest.to_hex_lowercase());
}

/// Whether upload tagging is enabled. Disabled by default (tagging costs an
/// extra set_tags round-trip per upload and nothing here reads the tags back);
/// enable via KCI_STORAGE_ENABLE_UPLOAD_TAGS=1/true/yes when a backend
/// lifecycle rule needs the owner/retention index tags.
fn upload_tags_enabled() -> bool {
    std::env::var("KCI_STORAGE_ENABLE_UPLOAD_TAGS")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Build blob index tags for a new upload: owner (when known) plus the
/// optional configured retention tag. An Azure lifecycle management rule
/// matching the retention tag (blobIndexMatch) can then expire the blob.
/// Returns None when there is nothing to tag.
fn upload_tags(owner_email: Option<String>) -> Option<Tags> {
    // Tagging costs an extra set_tags round-trip per upload and is off by
    // default; enable via KCI_STORAGE_ENABLE_UPLOAD_TAGS when a backend
    // lifecycle rule consumes the owner/retention index tags.
    if !upload_tags_enabled() {
        return None;
    }

    let mut pairs: Vec<(String, String)> = Vec::new();

    if let Some(email) = owner_email {
        let sanitized = sanitize_tag_component(&email);
        if sanitized != email {
            debug_log!(
                "Sanitized owner tag value from '{}' to '{}'",
                email,
                sanitized
            );
        }
        // Ensure non-empty value
        let final_value = if sanitized.is_empty() {
            "_".to_string()
        } else {
            sanitized
        };
        pairs.push(("owner".to_string(), final_value));
    }

    if let Some((key, value)) = crate::get_retention_tag() {
        let key = sanitize_tag_component(&key);
        let value = sanitize_tag_component(&value);
        if !key.is_empty() && !value.is_empty() {
            pairs.push((key, value));
        } else {
            debug_log!("Retention tag is empty after sanitization, skipping");
        }
    }

    if pairs.is_empty() {
        return None;
    }
    let mut tags = Tags::new();
    for (key, value) in pairs {
        tags.insert(key, value);
    }
    Some(tags)
}

/// Read from the stream until the buffer is full or EOF is reached. A single
/// read() may return far less than the buffer size (e.g. one multipart
/// network chunk), which would otherwise turn every ~64KB into its own
/// put_block round-trip.
async fn read_full_chunk(
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = data.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Write file to Azure blob storage using streaming (new version)
async fn write_file_to_blob_streaming(
    filename: String,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    owner_email: Option<String>,
) -> (&'static str, usize) {
    let blob_client = azure_blob_client(filename.as_str());

    let chunk_size = 10 * 1024 * 1024; // 10MB chunks
    // Probe with a small buffer first so many parallel small-file uploads
    // (the common archive case) don't each pin a 10MB allocation; only grow
    // to a full chunk when the file turns out to be larger than the probe.
    let probe_size = 256 * 1024;
    let mut buffer = vec![0u8; probe_size];
    let mut first_len = match read_full_chunk(data, &mut buffer).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Error reading stream: {:?}", e);
            return ("OK", 0);
        }
    };
    if first_len == probe_size {
        buffer.resize(chunk_size, 0);
        first_len += match read_full_chunk(data, &mut buffer[probe_size..]).await {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error reading stream: {:?}", e);
                return ("OK", 0);
            }
        };
    }

    // Whole file fits in one chunk: upload with single-shot Put Blob (one
    // round-trip) instead of put_block + put_block_list.
    if first_len < chunk_size {
        buffer.truncate(first_len);
        match blob_client
            .put_block_blob(buffer)
            .content_type(cont_type)
            .await
        {
            Ok(_) => {
                debug_log!("Uploaded {} bytes via put_blob", first_len);
                // Set upload tags (owner + retention); set_tags replaces the
                // whole tag set, so all tags must go in a single call
                if let Some(tags) = upload_tags(owner_email) {
                    match blob_client.set_tags(tags).await {
                        Ok(_) => {
                            debug_log!("Upload tags set successfully");
                        }
                        Err(e) => {
                            eprintln!("Error setting upload tags: {:?}", e);
                        }
                    }
                }
                return ("OK", first_len);
            }
            Err(e) => {
                eprintln!("Error uploading blob: {:?}", e);
                return ("OK", 0);
            }
        }
    }

    // Larger file: stream it as a list of blocks
    let mut total_bytes_uploaded: usize = 0;
    let mut chunk_len = first_len;
    let mut blocks = BlockList::default();

    while chunk_len > 0 {
        buffer.truncate(chunk_len);
        let block_id = BlockId::new(hex::encode(total_bytes_uploaded.to_le_bytes()));
        blocks
            .blocks
            .push(BlobBlockType::Uncommitted(block_id.clone()));
        match blob_client.put_block(block_id, buffer).await {
            Ok(_) => {
                total_bytes_uploaded += chunk_len;
                debug_log!("Uploaded {} bytes", total_bytes_uploaded);
            }
            Err(e) => {
                eprintln!("Error uploading block: {:?}", e);
                break;
            }
        }
        buffer = vec![0u8; chunk_size];
        chunk_len = match read_full_chunk(data, &mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error reading stream: {:?}", e);
                break;
            }
        };
    }
    match blob_client
        .put_block_list(blocks)
        .content_type(cont_type)
        .await
    {
        Ok(_) => {
            debug_log!("Block list uploaded");
            let blob_url_res = blob_client.url();
            match blob_url_res {
                Ok(blob_url) => {
                    debug_log!("Blob URL: {}", blob_url);
                }
                Err(e) => {
                    eprintln!("Error getting blob URL: {:?}", e);
                }
            }

            // Set upload tags (owner + retention); set_tags replaces the
            // whole tag set, so all tags must go in a single call
            if let Some(tags) = upload_tags(owner_email) {
                match blob_client.set_tags(tags).await {
                    Ok(_) => {
                        debug_log!("Upload tags set successfully");
                    }
                    Err(e) => {
                        eprintln!("Error setting upload tags: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error uploading block list: {:?}", e);
        }
    }
    ("OK", total_bytes_uploaded)
}

/// Write file to Azure blob storage (legacy version using Vec<u8>)
/// TBD: Rework, do not keep whole file as Vec<u8> in memory!!!
#[allow(dead_code)]
async fn write_file_to_blob(
    filename: String,
    data: Vec<u8>,
    cont_type: String,
    owner_email: Option<String>,
) -> &'static str {
    /* store data in temporary file, filename is just hexadecimal file name */
    let folder = Builder::new().prefix("temp").tempdir_in("./").unwrap();
    let file_path = folder.path().display().to_string();
    let mut f_write = Builder::new()
        .prefix("upload")
        .suffix(".temp")
        .tempfile_in(file_path)
        .unwrap();
    f_write.write_all(&data).unwrap();
    // TODO: Is there simpler way? Maybe just rewind the file to beginning?
    let mut f = f_write.reopen().unwrap();
    //let fname_str = f.path().display().to_string();
    let blob_client = azure_blob_client(filename.as_str());

    let mut total_bytes_uploaded: usize = 0;
    let chunk_size = 10;
    let mut blocks = BlockList::default();

    calculate_checksum(&filename, &data);
    loop {
        let mut buffer = vec![0; chunk_size * 1024 * 1024];
        let bytes_read = f.read(&mut buffer);
        match bytes_read {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    break;
                }
                buffer.truncate(bytes_read);
                let block_id = BlockId::new(hex::encode(total_bytes_uploaded.to_le_bytes()));
                blocks
                    .blocks
                    .push(BlobBlockType::Uncommitted(block_id.clone()));
                match blob_client.put_block(block_id, buffer).await {
                    Ok(_) => {
                        total_bytes_uploaded += bytes_read;
                        debug_log!("Uploaded {} bytes", total_bytes_uploaded);
                    }
                    Err(e) => {
                        eprintln!("Error uploading block: {:?}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading file: {:?}", e);
                break;
            }
        }
    }
    match blob_client
        .put_block_list(blocks)
        .content_type(cont_type)
        .await
    {
        Ok(_) => {
            debug_log!("Block list uploaded");
            let blob_url_res = blob_client.url();
            match blob_url_res {
                Ok(blob_url) => {
                    debug_log!("Blob URL: {}", blob_url);
                }
                Err(e) => {
                    eprintln!("Error getting blob URL: {:?}", e);
                }
            }

            // Set upload tags (owner + retention); set_tags replaces the
            // whole tag set, so all tags must go in a single call
            if let Some(tags) = upload_tags(owner_email) {
                match blob_client.set_tags(tags).await {
                    Ok(_) => {
                        debug_log!("Upload tags set successfully");
                    }
                    Err(e) => {
                        eprintln!("Error setting upload tags: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error uploading block list: {:?}", e);
        }
    }
    "OK"
}

/// Get headers from file (Maybe should be moved to a separate module, its not Azure specific)
fn get_headers_from_file(filename: String) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let file_content = read_to_string(filename).unwrap();
    for line in file_content.lines() {
        // Split only on the first ':' so values like times (HH:MM:SS) are preserved
        if let Some((name, value)) = line.split_once(':') {
            let key = HeaderName::from_bytes(name.trim().as_bytes()).unwrap();
            let value = HeaderValue::from_str(value.trim()).unwrap();
            headers.insert(key, value);
        }
    }
    headers
}

/// Save headers(Azure) to file
fn save_headers_to_file(filename: String, headers: HeaderMap) {
    let f = File::create(&filename);
    match f {
        Ok(mut f) => {
            for (key, value) in headers.iter() {
                let key_lower = key.as_str().to_lowercase();
                let line = format!("{}:{}\n", key_lower, value.to_str().unwrap());
                // TBD: Filter out some names?
                f.write_all(line.as_bytes()).unwrap();
            }
        }
        Err(e) => {
            eprintln!("Error creating headers file {}: {:?}", filename, e);
        }
    }
}

/// Get file from Azure blob storage
async fn get_file_from_blob(filename: String) -> ReceivedFile {
    let azure_cfg = get_azure_credentials("azure");
    //println!("get_file_from_blob {}", filename);
    let storage_sastoken = azure_cfg.sastoken.as_str();
    let blob_client = azure_blob_client(filename.as_str());
    let blob_url_res = blob_client.url();
    let mut received_file = ReceivedFile {
        original_filename: "".to_string(),
        cached_filename: "".to_string(),
        headers: HeaderMap::new(),
        valid: false,
    };
    received_file.original_filename = filename.clone();

    let mut blob_url = match blob_url_res {
        Ok(url) => url.to_string(),
        Err(e) => {
            eprintln!("Error getting blob URL: {:?}", e);
            return received_file;
        }
    };
    // append SAS token to blob URL
    blob_url.push_str(storage_sastoken);
    // we generate a hash of the filename to use as cache filename, sharded by
    // the first hex byte of the digest so no single directory grows unbounded
    let hash = sha2_512::default().update(filename.as_bytes()).finalize();
    let digest = hash.digest();
    let cache_hex = digest.to_hex_lowercase().to_string();
    let (content_path, headers_path) = crate::storcaching::cache_file_paths("cache", &cache_hex);
    let cache_filename = content_path.to_string_lossy().into_owned();
    let cache_filename_headers = headers_path.to_string_lossy().into_owned();
    // check if cache file exists
    if std::path::Path::new(&cache_filename).exists() {
        // check if headers file exists, and if not wait up to 300 seconds
        // This is to avoid race condition, when we start to download file, but it is not yet completed
        // and second request to same file downloads incomplete file
        let mut headers_file_exists = false;
        for seconds in 0..300 {
            if std::path::Path::new(&cache_filename_headers).exists() {
                headers_file_exists = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            debug_log!(
                "Waiting for headers file {} to exist: {} seconds",
                cache_filename_headers,
                seconds
            );
        }

        if !headers_file_exists {
            eprintln!("Headers file {} does not exist", cache_filename_headers);
            return received_file;
        }
        //println!("Cache file {} exists", cache_filename);
        // is cached file non-zero length?
        // is cached file non-zero length?
        let metadata = std::fs::metadata(&cache_filename).unwrap();
        if metadata.len() > 0 {
            //println!("Cache file {} is non-zero length", cache_filename);
            received_file.cached_filename = cache_filename;
            received_file.headers = get_headers_from_file(cache_filename_headers);
            received_file.valid = true;
            return received_file;
        } else {
            // delete cache file and headers
            debug_log!("Cache file {} is zero length, deleting", cache_filename);
            match std::fs::remove_file(&cache_filename) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "Error deleting cached file {}: {:?}",
                        cache_filename_headers, e
                    );
                    return received_file;
                }
            }
            match std::fs::remove_file(&cache_filename_headers) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "Error deleting cached file {}: {:?}",
                        cache_filename_headers, e
                    );
                    return received_file;
                }
            }
        }
    }
    debug_log!(
        "Downloading blob to cache file {} from {}",
        cache_filename,
        blob_url
    );
    let response = http_client().get(blob_url).send().await;
    match response {
        Ok(response) => {
            debug_log!("Azure response: {:?}", response);
            // is status anything else than 200?
            // TODO: Do we need to return headers as well or it is data leakage?
            if response.status() != 200 {
                let status = response.status();
                let headers = response.headers().clone();
                let ms_error_code = headers
                    .get("x-ms-error-code")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<missing>");
                let ms_request_id = headers
                    .get("x-ms-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<missing>");
                let content_type = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<missing>");
                let body_preview = match response.bytes().await {
                    Ok(bytes) => {
                        let mut preview = String::from_utf8_lossy(&bytes).into_owned();
                        const MAX_LEN: usize = 4096;
                        if preview.len() > MAX_LEN {
                            preview.truncate(MAX_LEN);
                            preview.push_str("…<truncated>");
                        }
                        preview
                    }
                    Err(e) => format!("<failed to read body: {e}>"),
                };

                eprintln!(
                    "Error getting blob: {status} (x-ms-error-code={ms_error_code}, x-ms-request-id={ms_request_id}, content-type={content_type}) body={body_preview}"
                );
                return received_file;
            }
            received_file.headers = response.headers().clone();
            let resp_headers = response.headers().clone();
            let body = response.bytes().await.unwrap();
            // ensure the shard subdirectory exists before writing into it
            if let Err(e) = crate::storcaching::ensure_shard_dir("cache", &cache_hex) {
                eprintln!("Error creating cache shard directory: {:?}", e);
                return received_file;
            }
            // just write all to cache file
            let mut f = File::create(&cache_filename).unwrap();
            f.write_all(&body).unwrap();
            // write headers
            save_headers_to_file(cache_filename_headers, resp_headers);
            received_file.cached_filename = cache_filename;
            received_file.valid = true;
        }
        Err(e) => {
            eprintln!("Error getting blob: {:?}", e);
        }
    }
    received_file
}

// Implement set tags for Azure blob storage
// tags are in format "key=value"
#[allow(dead_code)]
async fn azure_set_filename_tags(
    filename: String,
    user_tags: Vec<(String, String)>,
) -> Result<String, String> {
    let blob_client = azure_blob_client(filename.as_str());
    let mut tags = Tags::new();
    // Iterate and add tags after sanitizing key and value
    for (key, value) in user_tags {
        let sanitized_key = sanitize_tag_component(&key);
        let sanitized_value = sanitize_tag_component(&value);
        if sanitized_key != key || sanitized_value != value {
            debug_log!(
                "Sanitized tag '{}'='{}' -> '{}'='{}'",
                key,
                value,
                sanitized_key,
                sanitized_value
            );
        }
        if sanitized_key.is_empty() {
            debug_log!("Skipping tag with empty key after sanitization: '{}'", key);
            continue;
        }
        let final_value = if sanitized_value.is_empty() {
            "_".to_string()
        } else {
            sanitized_value
        };
        tags.insert(sanitized_key, final_value);
    }
    let res = blob_client.set_tags(tags).await;
    match res {
        Ok(_) => Ok(String::from("OK")),
        Err(e) => Err(e.to_string()),
    }
}

#[allow(dead_code)]
async fn azure_list_files(_directory: String) -> Vec<String> {
    let listbldr = azure_container_client().list_blobs();
    let mut liststream = listbldr.into_stream();
    let mut listing = Vec::new();
    while let Some(Ok(page)) = liststream.next().await {
        let blobs = page.blobs.items;
        for blob in blobs {
            let blob_name = match blob {
                BlobItem::Blob(blob) => blob.name,
                BlobItem::BlobPrefix(blob_prefix) => blob_prefix.name,
            };
            listing.push(blob_name.clone());
        }
        debug_log!("Listing count: {}", listing.len());
    }
    //println!("Listing: {:?}", listing);
    listing
}

/// Implement Driver trait for AzureDriver
#[async_trait]
impl super::Driver for AzureDriver {
    async fn write_file(
        &self,
        filename: String,
        data: Vec<u8>,
        cont_type: String,
        owner_email: Option<String>,
    ) -> String {
        let filenameret = filename.clone();
        write_file_to_blob(filename, data, cont_type, owner_email).await;
        filenameret
    }
    async fn write_file_streaming(
        &self,
        filename: String,
        data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        cont_type: String,
        owner_email: Option<String>,
    ) -> (String, usize) {
        let (_status, size) =
            write_file_to_blob_streaming(filename.clone(), data, cont_type, owner_email).await;
        (filename, size)
    }
    async fn tag_file(
        &self,
        filename: String,
        user_tags: Vec<(String, String)>,
    ) -> Result<String, String> {
        azure_set_filename_tags(filename, user_tags).await
    }
    async fn get_file(&self, filename: String) -> ReceivedFile {
        get_file_from_blob(filename).await
    }
    // Disabled: listing files on Azure Blob Storage is extremely slow due to
    // the flat namespace requiring enumeration of all blobs with prefix filtering.
    // For large containers this can take minutes and time out.
    // The HTTP handler (ax_list_files) returns 403 Forbidden for Azure backends.
    async fn list_files(&self, _directory: String) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_sas_token;

    #[test]
    fn sas_token_is_left_empty() {
        assert_eq!(normalize_sas_token(""), "");
        assert_eq!(normalize_sas_token("   "), "");
    }

    #[test]
    fn sas_token_is_left_intact_when_prefixed() {
        assert_eq!(normalize_sas_token("?sv=1"), "?sv=1");
        assert_eq!(normalize_sas_token(" ?sv=1 "), "?sv=1");
    }

    #[test]
    fn sas_token_is_prefixed_when_missing_question_mark() {
        assert_eq!(normalize_sas_token("sv=1"), "?sv=1");
        assert_eq!(normalize_sas_token(" sv=1 "), "?sv=1");
    }
}
