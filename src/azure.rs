// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

pub struct AzureDriver;

impl AzureDriver {
    pub fn new() -> Self {
        AzureDriver
    }
}

use crate::{Args, ReceivedFile};
use axum::http::{HeaderName, HeaderValue};
use azure_storage::StorageCredentials;
use azure_storage_blobs::prelude::{BlobBlockType, BlockId, BlockList, ClientBuilder, Tags};
use chksum_hash_sha2_512 as sha2_512;
use clap::Parser;
use headers::HeaderMap;
use hex;
use reqwest::Client;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use tempfile::Builder;
use toml::Table;
use std::fs::read_to_string;

#[derive(Deserialize)]
struct AzureConfig {
    account: String,
    key: String,
    container: String,
    sastoken: String,
}

/// Get Azure credentials from config.toml
fn get_azure_credentials(name: &str) -> AzureConfig {
    let args = Args::parse();
    let cfg_file = args.config_file;
    let cfg_content = std::fs::read_to_string(cfg_file).unwrap();
    let cfg: Table = toml::from_str(&cfg_content).unwrap();
    let azure_cfg = cfg.get(name).unwrap();
    let account = azure_cfg.get("account").unwrap().as_str().unwrap();
    let key = azure_cfg.get("key").unwrap().as_str().unwrap();
    let container = azure_cfg.get("container").unwrap().as_str().unwrap();
    let sastoken = azure_cfg.get("sastoken").unwrap().as_str().unwrap();
    //println!("Azure account: {} key: {} sastoken: {} container: {}", account, key, sastoken, container);
    return AzureConfig {
        account: account.to_string(),
        key: key.to_string(),
        container: container.to_string(),
        sastoken: sastoken.to_string(),
    };
}

/// Write file to Azure blob storage
/// TBD: Rework, do not keep whole file as Vec<u8> in memory!!!
async fn write_file_to_blob(filename: String, data: Vec<u8>, cont_type: String) -> &'static str {
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
                        println!("Uploaded {} bytes", total_bytes_uploaded);
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
            println!("Block list uploaded");
            let blob_url_res = blob_client.url();
            match blob_url_res {
                Ok(blob_url) => {
                    println!("Blob URL: {}", blob_url);
                }
                Err(e) => {
                    eprintln!("Error getting blob URL: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Error uploading block list: {:?}", e);
        }
    }
    return "OK";
}

/// Get headers from file (Maybe should be moved to a separate module, its not Azure specific)
fn get_headers_from_file(filename: String) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let file_content = read_to_string(filename).unwrap();
    for line in file_content.lines() {
        // Use the variable here
        let parts: Vec<&str> = line.split(":").collect();
        if parts.len() == 2 {
            let key = HeaderName::from_bytes(parts[0].trim().as_bytes()).unwrap();
            let value = HeaderValue::from_str(parts[1].trim()).unwrap();
            headers.insert(key, value);
        }
    }
    return headers;
}

/// Save headers(Azure) to file
fn save_headers_to_file(filename: String, headers: HeaderMap) {
    let f = File::create(&filename);
    match f {
        Ok(mut f) => {
            for (key, value) in headers.iter() {
                let line = format!("{}:{}\n", key, value.to_str().unwrap());
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
        //println!("Cache file {} exists", cache_filename);
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
            println!("Cache file {} is zero length, deleting", cache_filename);
            match std::fs::remove_file(&cache_filename) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "Error deleting cached file {}: {:?}",
                        cache_filename_headers, e
                    );
                }
            }
            match std::fs::remove_file(&cache_filename_headers) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "Error deleting cached file {}: {:?}",
                        cache_filename_headers, e
                    );
                }
            }
        }
    }
    /*
    println!(
        "Downloading blob to cache file {} from {}",
        cache_filename, blob_url
    );
    */
    let client = Client::new();
    let response = client.get(blob_url).send().await;
    match response {
        Ok(response) => {
            println!("Response: {:?}", response);
            // is status anything else than 200?
            // TODO: Do we need to return headers as well or it is data leakage?
            if response.status() != 200 {
                eprintln!("Error getting blob: {:?}", response.status());
                return received_file;
            }
            save_headers_to_file(cache_filename_headers, response.headers().clone());
            received_file.headers = response.headers().clone();
            let body = response.bytes().await.unwrap();
            // just write all to cache file
            let mut f = File::create(&cache_filename).unwrap();
            f.write_all(&body).unwrap();
            // write headers

            received_file.cached_filename = cache_filename;
            received_file.valid = true;
        }
        Err(e) => {
            eprintln!("Error getting blob: {:?}", e);
        }
    }
    return received_file;
}

// Implement set tags for Azure blob storage
// tags are in format "key=value"
async fn azure_set_filename_tags(filename: String, user_tags: Vec<(String, String)>) -> Result<String, String> {
    let azure_cfg = Arc::new(get_azure_credentials("azure"));
    let storage_account = azure_cfg.account.as_str();
    let storage_key = azure_cfg.key.clone();
    let storage_container = azure_cfg.container.as_str();
    let storage_blob = filename.as_str();
    let storage_credential = StorageCredentials::access_key(storage_account, storage_key);
    let blob_client = ClientBuilder::new(storage_account, storage_credential)
        .blob_client(storage_container, storage_blob);
    let mut tags = Tags::new();
    // iterate and add tags, tags are in format "
    for tag in user_tags {
        let (tag, value) = tag;
        tags.insert(tag, value);
    }
    let res = blob_client.set_tags(tags).await;
    match res {
        Ok(_) => {
            return Ok(String::from("OK"));
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }
}

/// Implement Driver trait for AzureDriver
impl super::Driver for AzureDriver {
    fn write_file(&self, filename: String, data: Vec<u8>, cont_type: String) -> String {
        let filenameret = filename.clone();
        /* Call async write_file_to_blob use tokio::task::block_in_place */
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(write_file_to_blob(filename, data, cont_type));
        });
        return filenameret;
    }
    fn tag_file(&self, filename: String, user_tags: Vec<(String, String)>) -> Result<String, String> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ret = rt.block_on(azure_set_filename_tags(filename, user_tags));
        return ret;
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
        return received_file;
    }
}
