// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

//! On-disk download cache shared by the remote object-store drivers (Azure,
//! S3). Objects are fetched once into `cache/`, sharded by the hash of their
//! normalized key, as a `.content` file plus a `.headers` sidecar, and served
//! from there afterwards. Housekeeping lives in `storcaching`.

use crate::{CacheState, ReceivedFile};
use axum::http::{HeaderName, HeaderValue};
use bytes::Bytes;
use chksum_hash_sha2_512 as sha2_512;
use futures::{Stream, StreamExt};
use headers::HeaderMap;
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Cache root, relative to the working directory.
pub(crate) const CACHE_DIR: &str = "cache";

/// Content and headers paths for `key`, which must already be normalized the
/// way the driver addresses the object, so aliases share one entry.
pub(crate) fn cache_paths(cache_dir: &str, key: &str) -> (PathBuf, PathBuf) {
    let hash = sha2_512::default().update(key.as_bytes()).finalize();
    crate::storcaching::cache_file_paths(cache_dir, &hash.digest().to_hex_lowercase())
}

pub(crate) fn remove_cache_entry(content: &Path, headers: &Path) -> Result<(), String> {
    for (path, is_content) in [(headers, false), (content, true)] {
        match std::fs::remove_file(path) {
            Ok(()) => {
                if is_content {
                    crate::storcaching::note_cache_file_removed();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Failed to invalidate cache: {e}")),
        }
    }
    Ok(())
}

/// Drop the cached copy of `key` so a re-upload is not served stale.
pub(crate) fn invalidate(cache_dir: &str, key: &str) -> Result<(), String> {
    let (content, headers) = cache_paths(cache_dir, key);
    remove_cache_entry(&content, &headers)
}

/// Read a cached headers sidecar. Returns None when the file is not there yet
/// (another request is still downloading) or cannot be read. Malformed lines
/// are skipped rather than panicking a request handler.
fn read_headers_file(path: &Path) -> Option<HeaderMap> {
    let file_content = read_to_string(path).ok()?;
    let mut headers = HeaderMap::new();
    for line in file_content.lines() {
        // Split only on the first ':' so values like times (HH:MM:SS) are preserved
        if let Some((name, value)) = line.split_once(':') {
            if let (Ok(key), Ok(value)) = (
                HeaderName::from_bytes(name.trim().as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) {
                headers.insert(key, value);
            }
        }
    }
    Some(headers)
}

/// Save backend response headers to file. Blocking — call it from a blocking
/// thread. Built in one buffer so the sidecar lands in a single write.
fn save_headers_to_file(path: &Path, headers: &HeaderMap) {
    let mut body = String::new();
    for (key, value) in headers.iter() {
        // TBD: Filter out some names?
        let Ok(value) = value.to_str() else {
            continue;
        };
        body.push_str(&key.as_str().to_lowercase());
        body.push(':');
        body.push_str(value);
        body.push('\n');
    }
    match File::create(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(body.as_bytes()) {
                eprintln!("Error writing headers file {}: {:?}", path.display(), e);
            }
        }
        Err(e) => {
            eprintln!("Error creating headers file {}: {:?}", path.display(), e);
        }
    }
}

/// Outcome of inspecting the on-disk cache entry for an object.
pub(crate) enum CacheProbe {
    /// Content and headers are both present; the content file is already open.
    Hit {
        file: File,
        size: u64,
        headers: HeaderMap,
    },
    /// Nothing usable cached; fetch from the backend.
    Miss,
    /// A broken entry that could not be cleaned up; fail the request.
    Broken,
}

/// Inspect (and, when stale, clean up) the cache entry for an object.
///
/// Blocking — call it from a blocking thread. Everything the GET handler needs
/// is collected here in one hop: the open content handle, its size taken from
/// that same handle, and the parsed headers. Opening rather than stat-then-open
/// also closes the window where cache eviction removes the file in between.
pub(crate) fn probe_cache(content_path: &Path, headers_path: &Path) -> CacheProbe {
    let file = match File::open(content_path) {
        Ok(file) => file,
        Err(_) => return CacheProbe::Miss,
    };

    let size = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            eprintln!(
                "Error reading metadata of {}: {:?}",
                content_path.display(),
                e
            );
            return CacheProbe::Miss;
        }
    };

    match read_headers_file(headers_path) {
        Some(headers) => CacheProbe::Hit {
            file,
            size,
            headers,
        },
        None => {
            drop(file);
            match remove_cache_entry(content_path, headers_path) {
                Ok(()) => CacheProbe::Miss,
                Err(e) => {
                    eprintln!("{e}");
                    CacheProbe::Broken
                }
            }
        }
    }
}

/// Look `key` up in the cache. A hit comes back as a ready `ReceivedFile`
/// (`CacheState::Cached`), a miss as `Ok(None)`, and an entry that is broken
/// and could not be cleaned up as `Err(())`, which should fail the request.
pub(crate) async fn lookup(
    cache_dir: &str,
    filename: &str,
    key: &str,
) -> Result<Option<ReceivedFile>, ()> {
    let (content_path, headers_path) = cache_paths(cache_dir, key);
    let content = content_path.clone();
    let probe =
        match tokio::task::spawn_blocking(move || probe_cache(&content, &headers_path)).await {
            Ok(probe) => probe,
            Err(e) => {
                eprintln!("Cache probe task failed: {e}");
                return Err(());
            }
        };
    match probe {
        CacheProbe::Hit {
            file,
            size,
            headers,
        } => {
            let mut received_file =
                ReceivedFile::not_found(filename.to_string(), CacheState::Cached);
            received_file.cached_filename = content_path.to_string_lossy().into_owned();
            received_file.headers = headers;
            received_file.valid = true;
            received_file.file = Some(file);
            received_file.size = size;
            Ok(Some(received_file))
        }
        CacheProbe::Broken => Err(()),
        CacheProbe::Miss => Ok(None),
    }
}

/// Stream an object body fetched from the backend into the cache, publish it
/// together with its headers, and return it ready to serve
/// (`CacheState::Uncached`). Any failure returns a not-found result and
/// leaves no partial entry behind.
pub(crate) async fn store<S, E>(
    cache_dir: &str,
    filename: &str,
    key: &str,
    headers: HeaderMap,
    mut body: S,
) -> ReceivedFile
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Debug,
{
    let mut received_file = ReceivedFile::not_found(filename.to_string(), CacheState::Uncached);
    let (content_path, headers_path) = cache_paths(cache_dir, key);
    let cache_hex = content_path
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let cache_filename = content_path.to_string_lossy().into_owned();
    debug_log!("Downloading {} to cache file {}", filename, cache_filename);
    // ensure the shard subdirectory exists before writing into it
    if let Err(e) = crate::storcaching::ensure_shard_dir(cache_dir, &cache_hex) {
        eprintln!("Error creating cache shard directory: {:?}", e);
        return received_file;
    }

    // Stream the body to a temporary file with asynchronous I/O. Publishing
    // it with an atomic rename prevents readers from seeing a partial cache
    // entry if the transfer is interrupted.
    let cache_temp_filename = format!("{}.{}.part", cache_filename, std::process::id());
    let mut f = match tokio::fs::File::create(&cache_temp_filename).await {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "Error creating temporary cache file {}: {:?}",
                cache_temp_filename, e
            );
            return received_file;
        }
    };

    while let Some(chunk) = body.next().await {
        let result = match chunk {
            Ok(chunk) => f.write_all(&chunk).await.map_err(|e| {
                format!(
                    "Error writing temporary cache file {}: {:?}",
                    cache_temp_filename, e
                )
            }),
            Err(e) => Err(format!("Error streaming {}: {:?}", filename, e)),
        };
        if let Err(e) = result {
            eprintln!("{e}");
            drop(f);
            let _ = tokio::fs::remove_file(&cache_temp_filename).await;
            return received_file;
        }
    }

    if let Err(e) = f.flush().await {
        eprintln!(
            "Error flushing temporary cache file {}: {:?}",
            cache_temp_filename, e
        );
        drop(f);
        let _ = tokio::fs::remove_file(&cache_temp_filename).await;
        return received_file;
    }
    drop(f);

    if let Err(e) = tokio::fs::rename(&cache_temp_filename, &cache_filename).await {
        eprintln!(
            "Error publishing cache file {} as {}: {:?}",
            cache_temp_filename, cache_filename, e
        );
        let _ = tokio::fs::remove_file(&cache_temp_filename).await;
        return received_file;
    }
    // Keep the housekeeping counter current so it does not have to walk
    // the cache to learn its size. Two racing downloads of the same
    // object both count here; the periodic recount corrects that.
    crate::storcaching::note_cache_file_added();

    // Publish the headers sidecar and open the freshly cached content
    // for the response in a single blocking hop.
    let sidecar_headers = headers.clone();
    let opened = tokio::task::spawn_blocking(move || {
        save_headers_to_file(&headers_path, &sidecar_headers);
        let file = File::open(&content_path).ok()?;
        let size = file.metadata().ok()?.len();
        Some((file, size))
    })
    .await;

    match opened {
        Ok(Some((file, size))) => {
            received_file.cached_filename = cache_filename;
            received_file.headers = headers;
            received_file.valid = true;
            received_file.file = Some(file);
            received_file.size = size;
        }
        Ok(None) => {
            eprintln!("Error opening freshly cached file {}", cache_filename);
        }
        Err(e) => {
            eprintln!("Cache publish task panicked: {}", e);
        }
    }
    received_file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_objects_are_cache_hits_and_orphans_are_removed_without_waiting() {
        let _counter_lock = crate::storcaching::COUNTER_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let content = dir.path().join("entry.content");
        let headers = dir.path().join("entry.headers");
        std::fs::write(&content, "").unwrap();
        std::fs::write(&headers, "content-type:application/octet-stream\n").unwrap();
        assert!(matches!(
            probe_cache(&content, &headers),
            CacheProbe::Hit { size: 0, .. }
        ));
        std::fs::remove_file(&headers).unwrap();
        std::fs::write(&content, "orphan").unwrap();
        assert!(matches!(probe_cache(&content, &headers), CacheProbe::Miss));
        assert!(!content.exists());
        std::fs::write(&content, "cached-old-version").unwrap();
        std::fs::write(&headers, "old-headers").unwrap();
        remove_cache_entry(&content, &headers).unwrap();
        assert!(!content.exists() && !headers.exists());
    }

    #[test]
    fn store_then_lookup_round_trips_and_invalidate_removes() {
        crate::storcaching::block_on_with_counter_lock(store_then_lookup());
    }

    async fn store_then_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        assert!(matches!(lookup(root, "a/b", "a/b").await, Ok(None)));

        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("\"abc\""));
        headers.insert(
            "last-modified",
            HeaderValue::from_static("Wed, 14 Oct 2026 00:00:00 GMT"),
        );
        let body = futures::stream::iter(vec![
            Ok::<_, std::io::Error>(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"world")),
        ]);
        let stored = store(root, "a/b", "a/b", headers, body).await;
        assert!(stored.valid);
        assert_eq!(stored.size, 11);
        assert!(matches!(stored.cache_state, CacheState::Uncached));

        let hit = lookup(root, "a/b", "a/b").await.unwrap().unwrap();
        assert!(matches!(hit.cache_state, CacheState::Cached));
        assert_eq!(hit.size, 11);
        assert_eq!(hit.headers.get("etag").unwrap(), "\"abc\"");
        // Times contain ':' and must survive the sidecar round trip.
        assert_eq!(
            hit.headers.get("last-modified").unwrap(),
            "Wed, 14 Oct 2026 00:00:00 GMT"
        );

        invalidate(root, "a/b").unwrap();
        assert!(matches!(lookup(root, "a/b", "a/b").await, Ok(None)));
    }

    #[test]
    fn failed_body_stream_leaves_no_entry() {
        crate::storcaching::block_on_with_counter_lock(failed_body_stream());
    }

    async fn failed_body_stream() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let body = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"partial")),
            Err(std::io::Error::other("injected")),
        ]);
        let stored = store(root, "k", "k", HeaderMap::new(), body).await;
        assert!(!stored.valid);
        assert!(matches!(lookup(root, "k", "k").await, Ok(None)));
        let shard = cache_paths(root, "k").0.parent().unwrap().to_path_buf();
        assert_eq!(std::fs::read_dir(shard).unwrap().count(), 0);
    }
}
