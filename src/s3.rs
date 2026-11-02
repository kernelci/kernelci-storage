// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.

//! S3-compatible object storage backend (AWS S3, MinIO, Garage, Hetzner,
//! Cloudflare R2, ...). Objects are fetched into the shared download cache
//! (`objcache`) and served from there, like the Azure driver does.

use crate::objcache::{self, CACHE_DIR};
use crate::objupload::{read_first_chunk, read_full_chunk, upload_tag_pairs, UPLOAD_CHUNK_SIZE};
use crate::{CacheState, ReceivedFile};
use async_trait::async_trait;
use axum::http::HeaderValue;
use bytes::Bytes;
use headers::HeaderMap;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path;
use object_store::{
    Attribute, Attributes, ObjectStore, ObjectStoreExt, PutMultipartOptions, PutOptions,
    PutPayload, TagSet, WriteMultipart,
};
use std::sync::OnceLock;
use toml::Table;

/// Multipart parts uploaded concurrently per upload. Bounds the memory one
/// upload holds to about this many `UPLOAD_CHUNK_SIZE` buffers.
const UPLOAD_PARALLEL_PARTS: usize = 4;

pub struct S3Driver;

impl S3Driver {
    pub fn new() -> Self {
        // Build the client now so a broken [s3] section fails at startup
        // rather than on the first request.
        let _ = s3_backend();
        S3Driver
    }
}

/*
Example config.toml section:

driver="s3"
[s3]
bucket="kernelci"              # required
region="us-east-1"             # optional
endpoint="https://s3.example"  # optional; for MinIO/Garage/Hetzner/R2
access_key_id="..."            # optional; else AWS_ACCESS_KEY_ID etc.
secret_access_key="..."
virtual_hosted_style=false     # optional, path-style by default
allow_http=false               # optional, for a local MinIO/Garage
prefix=""                      # optional key prefix inside the bucket
*/

#[derive(Debug, Default, PartialEq)]
struct S3Config {
    bucket: String,
    region: Option<String>,
    endpoint: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    virtual_hosted_style: Option<bool>,
    allow_http: Option<bool>,
    prefix: String,
}

fn string_setting(section: &Table, name: &str) -> Result<Option<String>, String> {
    match section.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|v| Some(v.to_string()))
            .ok_or_else(|| format!("s3.{name} must be a string")),
    }
}

fn bool_setting(section: &Table, name: &str) -> Result<Option<bool>, String> {
    match section.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("s3.{name} must be a boolean")),
    }
}

fn parse_config(config: &Table) -> Result<S3Config, String> {
    let section = config
        .get("s3")
        .and_then(|v| v.as_table())
        .ok_or("missing [s3] section")?;
    let bucket = string_setting(section, "bucket")?
        .filter(|b| !b.is_empty())
        .ok_or("s3.bucket is required")?;
    let access_key_id = string_setting(section, "access_key_id")?;
    let secret_access_key = string_setting(section, "secret_access_key")?;
    if access_key_id.is_some() != secret_access_key.is_some() {
        return Err("s3.access_key_id and s3.secret_access_key must be set together".to_string());
    }
    Ok(S3Config {
        bucket,
        region: string_setting(section, "region")?,
        endpoint: string_setting(section, "endpoint")?,
        access_key_id,
        secret_access_key,
        virtual_hosted_style: bool_setting(section, "virtual_hosted_style")?,
        allow_http: bool_setting(section, "allow_http")?,
        prefix: crate::normalize_storage_path(
            &string_setting(section, "prefix")?.unwrap_or_default(),
        )?,
    })
}

/// A store plus where its objects live in it and where they are cached.
/// Tests build one over `object_store::memory::InMemory`.
struct S3Backend {
    store: Box<dyn ObjectStore>,
    prefix: String,
    cache_dir: String,
}

/// Shared backend so every request reuses one client and connection pool.
/// `AWS_*` environment variables (credentials, region, endpoint, IAM/IRSA)
/// are honoured; values from config.toml override them.
fn s3_backend() -> &'static S3Backend {
    static BACKEND: OnceLock<S3Backend> = OnceLock::new();
    BACKEND.get_or_init(|| {
        let config = parse_config(crate::get_config_table()).unwrap_or_else(|error| {
            eprintln!("Invalid s3 configuration: {error}");
            std::process::exit(1);
        });
        let mut builder = AmazonS3Builder::from_env().with_bucket_name(&config.bucket);
        if let Some(region) = &config.region {
            builder = builder.with_region(region);
        }
        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        if let (Some(key_id), Some(secret)) = (&config.access_key_id, &config.secret_access_key) {
            builder = builder
                .with_access_key_id(key_id)
                .with_secret_access_key(secret);
        }
        // Path-style unless asked otherwise: it works with every
        // S3-compatible store, virtual-hosted style needs per-bucket DNS.
        builder =
            builder.with_virtual_hosted_style_request(config.virtual_hosted_style.unwrap_or(false));
        if let Some(allow_http) = config.allow_http {
            builder = builder.with_allow_http(allow_http);
        }
        let store = builder.build().unwrap_or_else(|error| {
            eprintln!("Invalid s3 configuration: {error}");
            std::process::exit(1);
        });
        S3Backend {
            store: Box::new(store),
            prefix: config.prefix,
            cache_dir: CACHE_DIR.to_string(),
        }
    })
}

/// Upload tags as an S3 tag set. Empty unless KCI_STORAGE_ENABLE_UPLOAD_TAGS
/// is set; Garage, for one, does not implement object tagging.
fn upload_tag_set(owner_email: Option<String>) -> TagSet {
    let mut tags = TagSet::default();
    for (key, value) in upload_tag_pairs(owner_email) {
        tags.push(&key, &value);
    }
    tags
}

/// HTTP ETags are quoted. S3 sends them that way, but not every store does,
/// and the GET handler compares the value byte for byte with If-None-Match.
fn quoted_etag(etag: &str) -> String {
    if etag.starts_with('"') || etag.starts_with("W/") {
        etag.to_string()
    } else {
        format!("\"{etag}\"")
    }
}

/// Stream `data` to `path`. Anything smaller than one chunk goes up in a
/// single PUT; larger streams use a multipart upload that is aborted on any
/// error, so no partial object is committed and no upload is left dangling.
async fn upload_stream(
    store: &dyn ObjectStore,
    path: &Path,
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    cont_type: String,
    tags: TagSet,
) -> Result<usize, String> {
    let mut attributes = Attributes::new();
    attributes.insert(Attribute::ContentType, cont_type.into());

    let first = read_first_chunk(data).await.map_err(|e| e.to_string())?;
    if first.len() < UPLOAD_CHUNK_SIZE {
        let size = first.len();
        let options = PutOptions {
            tags,
            attributes,
            ..Default::default()
        };
        store
            .put_opts(path, PutPayload::from(first), options)
            .await
            .map_err(|e| format!("Object upload failed: {e}"))?;
        return Ok(size);
    }

    let options = PutMultipartOptions {
        tags,
        attributes,
        ..Default::default()
    };
    let upload = store
        .put_multipart_opts(path, options)
        .await
        .map_err(|e| format!("Multipart upload start failed: {e}"))?;
    let mut writer = WriteMultipart::new_with_chunk_size(upload, UPLOAD_CHUNK_SIZE);
    let mut total_bytes = first.len();
    writer.put(Bytes::from(first));

    let streamed: Result<(), String> = async {
        loop {
            writer
                .wait_for_capacity(UPLOAD_PARALLEL_PARTS)
                .await
                .map_err(|e| format!("Part upload failed: {e}"))?;
            let mut buffer = vec![0u8; UPLOAD_CHUNK_SIZE];
            let len = read_full_chunk(data, &mut buffer)
                .await
                .map_err(|e| e.to_string())?;
            if len == 0 {
                return Ok(());
            }
            buffer.truncate(len);
            writer.put(Bytes::from(buffer));
            total_bytes += len;
        }
    }
    .await;

    if let Err(e) = streamed {
        if let Err(abort_error) = writer.abort().await {
            eprintln!("Error aborting multipart upload of {path}: {abort_error}");
        }
        return Err(e);
    }
    // finish() aborts the upload itself when completing fails.
    writer
        .finish()
        .await
        .map_err(|e| format!("Multipart upload failed: {e}"))?;
    Ok(total_bytes)
}

impl S3Backend {
    /// Normalized object key for `filename`: the same form main.rs uses for
    /// locks (`storage_key`), and what the cache entry is hashed from.
    fn key(&self, filename: &str) -> Result<String, String> {
        let key = crate::normalize_storage_path(filename)?;
        if key.is_empty() {
            return Err("Empty object key".to_string());
        }
        Ok(key)
    }

    /// Location of `key` in the bucket. The optional prefix applies here only,
    /// not to the cache key.
    fn path(&self, key: &str) -> Result<Path, String> {
        let full = if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.prefix, key)
        };
        Path::parse(full).map_err(|e| e.to_string())
    }

    async fn write_streaming(
        &self,
        filename: &str,
        data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        cont_type: String,
        tags: TagSet,
    ) -> Result<usize, String> {
        let key = self.key(filename)?;
        let path = self.path(&key)?;
        // A re-upload must not keep serving the previous cached copy.
        objcache::invalidate(&self.cache_dir, &key)?;
        upload_stream(self.store.as_ref(), &path, data, cont_type, tags).await
    }

    async fn get_file(&self, filename: String) -> ReceivedFile {
        let not_found = || ReceivedFile::not_found(filename.clone(), CacheState::Uncached);
        let (key, path) = match self.key(&filename).and_then(|k| Ok((self.path(&k)?, k))) {
            Ok((path, key)) => (key, path),
            Err(e) => {
                debug_log!("Rejecting S3 key {}: {}", filename, e);
                return not_found();
            }
        };
        match objcache::lookup(&self.cache_dir, &filename, &key).await {
            Ok(Some(hit)) => return hit,
            Ok(None) => {}
            Err(()) => return not_found(),
        }
        debug_log!("Downloading object {} from S3", path);
        let result = match self.store.get(&path).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return not_found(),
            Err(e) => {
                eprintln!("Error getting object {}: {}", path, e);
                return not_found();
            }
        };

        // Only these three headers are read back by the GET handler.
        let mut headers = HeaderMap::new();
        let content_type = result
            .attributes
            .get(&Attribute::ContentType)
            .and_then(|v| HeaderValue::from_str(v.as_ref()).ok())
            .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream"));
        headers.insert("content-type", content_type);
        if let Some(etag) = result
            .meta
            .e_tag
            .as_deref()
            .and_then(|etag| HeaderValue::from_str(&quoted_etag(etag)).ok())
        {
            headers.insert("etag", etag);
        }
        let last_modified = result
            .meta
            .last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        if let Ok(value) = HeaderValue::from_str(&last_modified) {
            headers.insert("last-modified", value);
        }

        objcache::store(
            &self.cache_dir,
            &filename,
            &key,
            headers,
            result.into_stream(),
        )
        .await
    }
}

#[async_trait]
impl super::Driver for S3Driver {
    async fn write_file(
        &self,
        filename: String,
        data: Vec<u8>,
        cont_type: String,
        owner_email: Option<String>,
    ) -> String {
        let mut input = std::io::Cursor::new(data);
        let (filename, _) = self
            .write_file_streaming(filename, &mut input, cont_type, owner_email)
            .await;
        filename
    }
    async fn write_file_streaming(
        &self,
        filename: String,
        data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        cont_type: String,
        owner_email: Option<String>,
    ) -> (String, usize) {
        match s3_backend()
            .write_streaming(&filename, data, cont_type, upload_tag_set(owner_email))
            .await
        {
            Ok(size) => (filename, size),
            Err(e) => {
                eprintln!("S3 upload failed: {e}");
                (String::new(), 0)
            }
        }
    }
    async fn tag_file(
        &self,
        _filename: String,
        _user_tags: Vec<(String, String)>,
    ) -> Result<String, String> {
        // object_store can only set tags when an object is written.
        Err("Tagging existing objects is not supported by the S3 driver".to_string())
    }
    async fn get_file(&self, filename: String) -> ReceivedFile {
        s3_backend().get_file(filename).await
    }
    // Disabled for the same reason as on Azure: enumerating a flat namespace
    // is slow for large buckets. ax_list_files returns 403 for this backend.
    async fn list_files(&self, _directory: String) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objupload::FailedRead;
    use crate::storcaching::block_on_with_counter_lock;
    use object_store::memory::InMemory;

    fn backend(cache: &tempfile::TempDir, prefix: &str) -> S3Backend {
        S3Backend {
            store: Box::new(InMemory::new()),
            prefix: prefix.to_string(),
            cache_dir: cache.path().to_str().unwrap().to_string(),
        }
    }

    async fn read_back(backend: &S3Backend, filename: &str) -> (ReceivedFile, Vec<u8>) {
        let mut received = backend.get_file(filename.to_string()).await;
        let mut body = Vec::new();
        if let Some(file) = received.file.as_mut() {
            std::io::Read::read_to_end(file, &mut body).unwrap();
        }
        (received, body)
    }

    fn table(toml: &str) -> Table {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn config_requires_bucket_and_paired_credentials() {
        assert!(parse_config(&table("")).is_err());
        assert!(parse_config(&table("[s3]\nregion=\"x\"")).is_err());
        assert!(parse_config(&table("[s3]\nbucket=\"\"")).is_err());
        assert!(parse_config(&table("[s3]\nbucket=\"b\"\naccess_key_id=\"k\"")).is_err());
        assert!(parse_config(&table("[s3]\nbucket=\"b\"\nallow_http=\"yes\"")).is_err());
        assert_eq!(
            parse_config(&table("[s3]\nbucket=\"b\"")).unwrap(),
            S3Config {
                bucket: "b".to_string(),
                ..Default::default()
            }
        );
        let full = parse_config(&table(
            "[s3]\nbucket=\"b\"\nregion=\"garage\"\nendpoint=\"http://localhost:3900\"\n\
             access_key_id=\"k\"\nsecret_access_key=\"s\"\nvirtual_hosted_style=true\n\
             allow_http=true\nprefix=\"/a//b/\"",
        ))
        .unwrap();
        assert_eq!(full.region.as_deref(), Some("garage"));
        assert_eq!(full.allow_http, Some(true));
        assert_eq!(full.virtual_hosted_style, Some(true));
        assert_eq!(full.prefix, "a/b");
        assert!(parse_config(&table("[s3]\nbucket=\"b\"\nprefix=\"../x\"")).is_err());
    }

    #[test]
    fn etags_are_quoted_once() {
        assert_eq!(quoted_etag("abc"), "\"abc\"");
        assert_eq!(quoted_etag("\"abc\""), "\"abc\"");
        assert_eq!(quoted_etag("W/\"abc\""), "W/\"abc\"");
    }

    #[tokio::test]
    async fn uploads_store_exact_bytes_and_content_type() {
        let store = InMemory::new();
        for size in [
            0,
            16,
            UPLOAD_CHUNK_SIZE,
            UPLOAD_CHUNK_SIZE + 1,
            2 * UPLOAD_CHUNK_SIZE + 3,
        ] {
            let path = Path::parse(format!("obj/{size}")).unwrap();
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut input = std::io::Cursor::new(data.clone());
            let uploaded = upload_stream(
                &store,
                &path,
                &mut input,
                "text/plain".to_string(),
                TagSet::default(),
            )
            .await
            .unwrap();
            assert_eq!(uploaded, size);
            let result = store.get(&path).await.unwrap();
            assert_eq!(
                result
                    .attributes
                    .get(&Attribute::ContentType)
                    .map(|v| v.as_ref()),
                Some("text/plain")
            );
            assert_eq!(result.meta.size, size as u64);
            assert_eq!(result.bytes().await.unwrap().as_ref(), data.as_slice());
        }
    }

    #[tokio::test]
    async fn failed_reads_leave_no_object() {
        let store = InMemory::new();
        let path = Path::parse("broken").unwrap();
        // Before anything is sent.
        assert!(upload_stream(
            &store,
            &path,
            &mut FailedRead,
            "a/b".to_string(),
            TagSet::default()
        )
        .await
        .is_err());
        // In the middle of a multipart upload.
        let mut input = tokio::io::AsyncReadExt::chain(
            std::io::Cursor::new(vec![0u8; UPLOAD_CHUNK_SIZE + 5]),
            FailedRead,
        );
        assert!(upload_stream(
            &store,
            &path,
            &mut input,
            "a/b".to_string(),
            TagSet::default()
        )
        .await
        .is_err());
        assert!(matches!(
            store.head(&path).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }

    #[test]
    fn missing_objects_are_not_found_and_not_cached() {
        block_on_with_counter_lock(async {
            let cache = tempfile::tempdir().unwrap();
            let backend = backend(&cache, "");
            let (received, _) = read_back(&backend, "no/such/file").await;
            assert!(!received.valid);
            assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
        });
    }

    #[test]
    fn get_after_put_is_cached_and_reupload_invalidates() {
        block_on_with_counter_lock(async {
            let cache = tempfile::tempdir().unwrap();
            let backend = backend(&cache, "pre/fix");
            let mut input = std::io::Cursor::new(b"first".to_vec());
            backend
                .write_streaming(
                    "a/file.txt",
                    &mut input,
                    "text/plain".to_string(),
                    TagSet::default(),
                )
                .await
                .unwrap();
            // The prefix is applied in the bucket only.
            assert!(backend
                .store
                .head(&Path::parse("pre/fix/a/file.txt").unwrap())
                .await
                .is_ok());

            let (received, body) = read_back(&backend, "a/file.txt").await;
            assert!(received.valid);
            assert!(matches!(received.cache_state, CacheState::Uncached));
            assert_eq!(body, b"first");
            assert_eq!(received.headers.get("content-type").unwrap(), "text/plain");
            let etag = received.headers.get("etag").unwrap().to_str().unwrap();
            assert!(etag.starts_with('"') && etag.ends_with('"'));
            let last_modified = received.headers.get("last-modified").unwrap();
            assert!(last_modified.to_str().unwrap().ends_with(" GMT"));

            let (cached, body) = read_back(&backend, "a/file.txt").await;
            assert!(matches!(cached.cache_state, CacheState::Cached));
            assert_eq!(body, b"first");
            assert_eq!(cached.headers.get("etag"), received.headers.get("etag"));

            let mut input = std::io::Cursor::new(b"second".to_vec());
            backend
                .write_streaming(
                    "a/file.txt",
                    &mut input,
                    "text/plain".to_string(),
                    TagSet::default(),
                )
                .await
                .unwrap();
            let (fresh, body) = read_back(&backend, "a/file.txt").await;
            assert!(matches!(fresh.cache_state, CacheState::Uncached));
            assert_eq!(body, b"second");
        });
    }

    #[test]
    fn key_aliases_share_one_object_and_cache_entry() {
        block_on_with_counter_lock(async {
            let cache = tempfile::tempdir().unwrap();
            let backend = backend(&cache, "");
            let mut input = std::io::Cursor::new(b"x".to_vec());
            backend
                .write_streaming("/a//./b/", &mut input, "a/b".to_string(), TagSet::default())
                .await
                .unwrap();
            for alias in ["a/b", "a/./b", "/a/b/", "a//b"] {
                assert_eq!(backend.key(alias).unwrap(), "a/b");
                assert_eq!(
                    backend.key(alias).unwrap(),
                    crate::normalize_storage_path(alias).unwrap()
                );
                let (received, body) = read_back(&backend, alias).await;
                assert!(received.valid, "{alias}");
                assert_eq!(body, b"x");
            }
            // Fetched once, then served from one cache entry.
            assert_eq!(
                std::fs::read_dir(cache.path())
                    .unwrap()
                    .flat_map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap())
                    .filter(|f| f.as_ref().unwrap().path().extension().unwrap() == "content")
                    .count(),
                1
            );
            assert!(backend.key("a/../b").is_err());
            assert!(backend.key("/").is_err());
        });
    }
}
