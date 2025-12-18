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
use azure_storage_blobs::prelude::{BlobBlockType, BlockId, BlockList, ClientBuilder, Tags};
use chksum_hash_sha2_512 as sha2_512;
use futures::stream::StreamExt;
use headers::HeaderMap;
use reqwest::Client;
use serde::Deserialize;
use std::fs::read_to_string;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
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
        sastoken: sastoken.to_string(),
    }
}

fn calculate_checksum(filename: &String, data: &[u8]) {
    let hash = sha2_512::default().update(data).finalize();
    let digest = hash.digest();
    debug_log!("File: {} Checksum: {}", filename, digest.to_hex_lowercase());
}

/// Write file to Azure blob storage using streaming (new version)
async fn write_file_to_blob_streaming(
    filename: String,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    owner_email: Option<String>,
) -> (&'static str, usize) {
    let azure_cfg = Arc::new(get_azure_credentials("azure"));

    let storage_account = azure_cfg.account.as_str();
    let storage_key = azure_cfg.key.clone();
    let storage_container = azure_cfg.container.as_str();
    let storage_blob = filename.as_str();
    let storage_credential = StorageCredentials::access_key(storage_account, storage_key);
    let blob_client = ClientBuilder::new(storage_account, storage_credential)
        .blob_client(storage_container, storage_blob);

    let mut total_bytes_uploaded: usize = 0;
    let chunk_size = 10 * 1024 * 1024; // 10MB chunks
    let mut blocks = BlockList::default();

    loop {
        let mut buffer = vec![0u8; chunk_size];
        let bytes_read = data.read(&mut buffer).await;
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
                eprintln!("Error reading stream: {:?}", e);
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

            // Set owner tag if email is provided
            if let Some(email) = owner_email {
                let mut tags = Tags::new();
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
                tags.insert("owner".to_string(), final_value);
                match blob_client.set_tags(tags).await {
                    Ok(_) => {
                        debug_log!("Owner tag set successfully");
                    }
                    Err(e) => {
                        eprintln!("Error setting owner tag: {:?}", e);
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
async fn write_file_to_blob(
    filename: String,
    data: Vec<u8>,
    cont_type: String,
    owner_email: Option<String>,
) -> &'static str {
    let azure_cfg = Arc::new(get_azure_credentials("azure"));

    let storage_account = azure_cfg.account.as_str();
    let storage_key = azure_cfg.key.clone();
    let storage_container = azure_cfg.container.as_str();
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
    let storage_blob = filename.as_str();
    let storage_credential = StorageCredentials::access_key(storage_account, storage_key);
    let blob_client = ClientBuilder::new(storage_account, storage_credential)
        .blob_client(storage_container, storage_blob);

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

            // Set owner tag if email is provided
            if let Some(email) = owner_email {
                let mut tags = Tags::new();
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
                tags.insert("owner".to_string(), final_value);
                match blob_client.set_tags(tags).await {
                    Ok(_) => {
                        debug_log!("Owner tag set successfully");
                    }
                    Err(e) => {
                        eprintln!("Error setting owner tag: {:?}", e);
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
    let azure_cfg = Arc::new(get_azure_credentials("azure"));
    //println!("get_file_from_blob {}", filename);
    let storage_account = azure_cfg.account.as_str();
    let storage_key = azure_cfg.key.clone();
    let storage_container = azure_cfg.container.as_str();
    let storage_sastoken = azure_cfg.sastoken.as_str();
    let storage_blob = filename.as_str();
    let storage_credential = StorageCredentials::access_key(storage_account, storage_key);
    let blob_client = ClientBuilder::new(storage_account, storage_credential)
        .blob_client(storage_container, storage_blob);
    let blob_url_res = blob_client.url();
    let mut blob_url = "".to_string();
    let mut received_file = ReceivedFile {
        original_filename: "".to_string(),
        cached_filename: "".to_string(),
        headers: HeaderMap::new(),
        valid: false,
    };
    received_file.original_filename = filename.clone();

    match blob_url_res {
        Ok(url) => {
            //println!("Blob URL: {}", url);
            blob_url = url.to_string();
        }
        Err(e) => {
            eprintln!("Error getting blob URL: {:?}", e);
            return received_file;
        }
    }
    // append SAS token to blob URL
    blob_url.push_str(storage_sastoken);
    // we generate a hash of the filename to use as cache filename
    let hash = sha2_512::default().update(filename.as_bytes()).finalize();
    let digest = hash.digest();
    let cache_filename = format!("cache/{}.content", digest.to_hex_lowercase());
    let cache_filename_headers = format!("cache/{}.headers", digest.to_hex_lowercase());
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
            std::thread::sleep(std::time::Duration::from_millis(1000));
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
    let client = Client::new();
    let response = client.get(blob_url).send().await;
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
async fn azure_set_filename_tags(
    filename: String,
    user_tags: Vec<(String, String)>,
) -> Result<String, String> {
    let azure_cfg = Arc::new(get_azure_credentials("azure"));
    let storage_account = azure_cfg.account.as_str();
    let storage_key = azure_cfg.key.clone();
    let storage_container = azure_cfg.container.as_str();
    let storage_blob = filename.as_str();
    let storage_credential = StorageCredentials::access_key(storage_account, storage_key);
    let blob_client = ClientBuilder::new(storage_account, storage_credential)
        .blob_client(storage_container, storage_blob);
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

async fn azure_list_files(directory: String) -> Vec<String> {
    let azure_cfg = Arc::new(get_azure_credentials("azure"));
    let storage_account = azure_cfg.account.as_str();
    let storage_key = azure_cfg.key.clone();
    let storage_container = azure_cfg.container.as_str();
    let storage_credential = StorageCredentials::access_key(storage_account, storage_key);
    let container_r =
        ClientBuilder::new(storage_account, storage_credential).container_client(storage_container);
    let listbldr = container_r.list_blobs();
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
    fn write_file(
        &self,
        filename: String,
        data: Vec<u8>,
        cont_type: String,
        owner_email: Option<String>,
    ) -> String {
        let filenameret = filename.clone();
        /* Call async write_file_to_blob use tokio::task::block_in_place */
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(write_file_to_blob(filename, data, cont_type, owner_email));
        });
        filenameret
    }
    async fn write_file_streaming(
        &self,
        filename: String,
        data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        cont_type: String,
        owner_email: Option<String>,
    ) -> (String, usize) {
        let (_status, size) = write_file_to_blob_streaming(filename.clone(), data, cont_type, owner_email).await;
        (filename, size)
    }
    fn tag_file(
        &self,
        filename: String,
        user_tags: Vec<(String, String)>,
    ) -> Result<String, String> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ret = rt.block_on(azure_set_filename_tags(filename, user_tags));
        ret
    }
    fn get_file(&self, filename: String) -> ReceivedFile {
        /* Call async get_file_from_blob use tokio::task::block_in_place */
        let mut received_file = ReceivedFile {
            original_filename: "".to_string(),
            cached_filename: "".to_string(),
            headers: HeaderMap::new(),
            valid: false,
        };
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            received_file = rt.block_on(get_file_from_blob(filename));
        });
        received_file
    }
    fn list_files(&self, directory: String) -> Vec<String> {
        let mut ret = Vec::new();
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            ret = rt.block_on(azure_list_files(directory));
        });
        ret
    }
}
