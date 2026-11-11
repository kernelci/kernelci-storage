// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

pub struct AzureDriver;

impl AzureDriver {
    pub fn new() -> Self {
        AzureDriver
    }
}

use crate::objcache::{self, CACHE_DIR};
use crate::objupload::{
    read_first_chunk, read_full_chunk, sanitize_tag_component, upload_tag_pairs, UPLOAD_CHUNK_SIZE,
};
use crate::{debug_log, CacheState, ReceivedFile};
use async_trait::async_trait;
use azure_storage::StorageCredentials;
use azure_storage_blobs::container::operations::BlobItem;
use azure_storage_blobs::prelude::{
    BlobBlockType, BlobClient, BlockId, BlockList, ClientBuilder, ContainerClient, Tags,
};
use chksum_hash_sha2_512 as sha2_512;
use futures::stream::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use std::io::Read;
use std::io::Write;
use std::sync::OnceLock;
use tempfile::Builder;

#[derive(Deserialize)]
struct AzureConfig {
    account: String,
    key: String,
    container: String,
    sastoken: String,
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

/// Azure credentials from config.toml, parsed once and cached. The GET path
/// needs the SAS token on every request; re-reading and re-parsing the config
/// file there was blocking disk I/O on the async worker threads.
fn azure_credentials() -> &'static AzureConfig {
    static CONFIG: OnceLock<AzureConfig> = OnceLock::new();
    CONFIG.get_or_init(|| get_azure_credentials("azure"))
}

/// Get Azure credentials from config.toml
fn get_azure_credentials(name: &str) -> AzureConfig {
    let azure_cfg = crate::get_config_table().get(name).unwrap();
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
        let cfg = azure_credentials();
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

/// Write file to Azure blob storage using streaming (new version)
async fn write_file_to_blob_streaming(
    filename: String,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    owner_email: Option<String>,
) -> Result<usize, String> {
    invalidate_cached_blob(&filename)?;
    upload_blob_stream(
        azure_blob_client(&filename),
        data,
        cont_type,
        upload_tags(owner_email),
    )
    .await
}

async fn upload_blob_stream(
    blob_client: BlobClient,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    tags: Option<Tags>,
) -> Result<usize, String> {
    let chunk_size = UPLOAD_CHUNK_SIZE;
    let mut buffer = read_first_chunk(data).await.map_err(|e| e.to_string())?;
    let mut chunk_len = buffer.len();
    if chunk_len < chunk_size {
        let upload = blob_client.put_block_blob(buffer).content_type(cont_type);
        upload
            .await
            .map_err(|e| format!("Blob upload failed: {e}"))?;
        if let Some(tags) = tags {
            if let Err(e) = blob_client.set_tags(tags).await {
                eprintln!("Error setting upload tags: {e}");
            }
        }
        return Ok(chunk_len);
    }
    let mut total_bytes = 0usize;
    let mut blocks = BlockList::default();
    while chunk_len > 0 {
        buffer.truncate(chunk_len);
        let block_id = BlockId::new(hex::encode(total_bytes.to_le_bytes()));
        blob_client
            .put_block(block_id.clone(), buffer)
            .await
            .map_err(|e| format!("Block upload failed: {e}"))?;
        blocks.blocks.push(BlobBlockType::Uncommitted(block_id));
        total_bytes += chunk_len;
        buffer = vec![0u8; chunk_size];
        chunk_len = read_full_chunk(data, &mut buffer)
            .await
            .map_err(|e| e.to_string())?;
    }
    let upload = blob_client.put_block_list(blocks).content_type(cont_type);
    upload
        .await
        .map_err(|e| format!("Block list upload failed: {e}"))?;
    if let Some(tags) = tags {
        if let Err(e) = blob_client.set_tags(tags).await {
            eprintln!("Error setting upload tags: {e}");
        }
    }
    Ok(total_bytes)
}

pub(crate) fn normalize_blob_key(filename: &str) -> String {
    // Match BlobClient::url: edge slashes and dot segments are omitted, while
    // empty interior segments are preserved. Request validation rejects controls.
    filename
        .trim_matches('/')
        .split('/')
        .filter(|part| *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
fn blob_cache_paths(filename: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    objcache::cache_paths(CACHE_DIR, &normalize_blob_key(filename))
}

fn invalidate_cached_blob(filename: &str) -> Result<(), String> {
    objcache::invalidate(CACHE_DIR, &normalize_blob_key(filename))
}

/// Build blob index tags for a new upload (see `objupload::upload_tag_pairs`).
/// An Azure lifecycle management rule matching the retention tag
/// (blobIndexMatch) can then expire the blob. Returns None when there is
/// nothing to tag.
fn upload_tags(owner_email: Option<String>) -> Option<Tags> {
    let pairs = upload_tag_pairs(owner_email);
    if pairs.is_empty() {
        return None;
    }
    let mut tags = Tags::new();
    for (key, value) in pairs {
        tags.insert(key, value);
    }
    Some(tags)
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

/// Get file from Azure blob storage
async fn get_file_from_blob(filename: String) -> ReceivedFile {
    let storage_sastoken = azure_credentials().sastoken.as_str();
    let blob_client = azure_blob_client(filename.as_str());
    let blob_url_res = blob_client.url();
    let received_file = ReceivedFile::not_found(filename.clone(), CacheState::Uncached);

    let mut blob_url = match blob_url_res {
        Ok(url) => url.to_string(),
        Err(e) => {
            eprintln!("Error getting blob URL: {:?}", e);
            return received_file;
        }
    };
    // append SAS token to blob URL
    blob_url.push_str(storage_sastoken);
    // The cache is keyed by the same normalized name BlobClient::url uses,
    // so aliases of one blob share a cache entry.
    let key = normalize_blob_key(&filename);
    match objcache::lookup(CACHE_DIR, &filename, &key).await {
        Ok(Some(hit)) => return hit,
        Ok(None) => {}
        Err(()) => return received_file,
    }
    debug_log!("Downloading blob {} from {}", filename, blob_url);
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
            let headers = response.headers().clone();
            // Stream the body chunk by chunk without needing reqwest's
            // `stream` feature.
            let body = Box::pin(futures::stream::unfold(
                response,
                |mut response| async move {
                    match response.chunk().await {
                        Ok(Some(chunk)) => Some((Ok(chunk), response)),
                        Ok(None) => None,
                        Err(e) => Some((Err(e), response)),
                    }
                },
            ));
            objcache::store(CACHE_DIR, &filename, &key, headers, body).await
        }
        Err(e) => {
            eprintln!("Error getting blob: {:?}", e);
            received_file
        }
    }
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
        match write_file_to_blob_streaming(filename.clone(), data, cont_type, owner_email).await {
            Ok(size) => (filename, size),
            Err(e) => {
                eprintln!("Azure upload failed: {e}");
                (String::new(), 0)
            }
        }
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

#[cfg(test)]
mod upload_cache_tests {
    use super::*;
    use crate::objupload::FailedRead;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    async fn mock_blob(
        fail_request: usize,
    ) -> (BlobClient, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let app = axum::Router::new()
            .fallback(axum::routing::put(move |body: axum::body::Bytes| {
                let requests = requests.clone();
                async move {
                    let _ = body;
                    let number = requests.fetch_add(1, Ordering::SeqCst) + 1;
                    let status = if number == fail_request {
                        axum::http::StatusCode::FORBIDDEN
                    } else {
                        axum::http::StatusCode::CREATED
                    };
                    (
                        status,
                        [
                            ("etag", "mock-etag"),
                            ("last-modified", "Wed, 14 Oct 2026 00:00:00 GMT"),
                            ("date", "Wed, 14 Oct 2026 00:00:00 GMT"),
                            ("x-ms-request-id", "00000000-0000-0000-0000-000000000001"),
                            ("x-ms-request-server-encrypted", "true"),
                        ],
                        "",
                    )
                }
            }))
            .layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = ClientBuilder::with_location(
            azure_storage::CloudLocation::Emulator {
                address: "127.0.0.1".to_string(),
                port,
            },
            StorageCredentials::emulator(),
        )
        .blob_client("container", "file");
        (client, count, server)
    }

    #[test]
    fn cache_identity_matches_azure_url_aliases() {
        let client = |key: &str| {
            ClientBuilder::emulator()
                .blob_client("container", key)
                .url()
                .unwrap()
        };
        for alias in ["/a/file/", "a/./file", "a/././file"] {
            assert_eq!(client(alias), client("a/file"));
            assert_eq!(blob_cache_paths(alias), blob_cache_paths("a/file"));
        }
        assert_ne!(client("a//file"), client("a/file"));
        assert_ne!(blob_cache_paths("a//file"), blob_cache_paths("a/file"));
    }

    #[tokio::test]
    async fn upload_failures_do_not_commit_partial_streams_or_report_success() {
        let chunk = 10 * 1024 * 1024;
        // Single-shot, first block, and final block-list errors.
        for (size, fail_at) in [(0, 1), (16, 1), (chunk, 1), (chunk, 2)] {
            let (client, count, server) = mock_blob(fail_at).await;
            let mut input = std::io::Cursor::new(vec![0u8; size]);
            assert!(upload_blob_stream(
                client,
                &mut input,
                "application/octet-stream".to_string(),
                None
            )
            .await
            .is_err());
            assert_eq!(count.load(Ordering::SeqCst), fail_at);
            server.abort();
        }
        // A read failure after one successful block must not commit that block.
        let (client, count, server) = mock_blob(0).await;
        let mut input =
            tokio::io::AsyncReadExt::chain(std::io::Cursor::new(vec![0u8; chunk]), FailedRead);
        assert!(upload_blob_stream(
            client,
            &mut input,
            "application/octet-stream".to_string(),
            None
        )
        .await
        .is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        server.abort();
        // The initial read fails before any request is made.
        let (client, count, server) = mock_blob(0).await;
        assert!(upload_blob_stream(
            client,
            &mut FailedRead,
            "application/octet-stream".to_string(),
            None
        )
        .await
        .is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn empty_small_and_block_uploads_still_succeed() {
        for (size, expected_requests) in [(0, 1), (16, 1), (10 * 1024 * 1024 + 1, 3)] {
            let (client, count, server) = mock_blob(0).await;
            let mut input = std::io::Cursor::new(vec![0u8; size]);
            assert_eq!(
                upload_blob_stream(
                    client,
                    &mut input,
                    "application/octet-stream".to_string(),
                    None
                )
                .await
                .unwrap(),
                size
            );
            assert_eq!(count.load(Ordering::SeqCst), expected_requests);
            server.abort();
        }
    }
}
