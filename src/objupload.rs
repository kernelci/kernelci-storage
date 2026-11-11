// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

//! Upload helpers shared by the remote object-store drivers (Azure, S3).

use tokio::io::AsyncReadExt;

/// Upload part size. Large enough to keep the request count low, and above
/// the 5 MiB minimum S3 imposes on every multipart part but the last.
pub(crate) const UPLOAD_CHUNK_SIZE: usize = 10 * 1024 * 1024;
/// First read of an upload. Most artifacts are small, so the full chunk
/// buffer is only allocated once the stream turns out to be larger.
pub(crate) const UPLOAD_PROBE_SIZE: usize = 256 * 1024;

/// Read from the stream until the buffer is full or EOF is reached. A single
/// read() may return far less than the buffer size (e.g. one multipart
/// network chunk), which would otherwise turn every ~64KB into its own
/// block/part round-trip.
pub(crate) async fn read_full_chunk(
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

/// Read the first chunk of an upload: a probe read, extended to a full
/// `UPLOAD_CHUNK_SIZE` only when the probe filled up. A result shorter than
/// `UPLOAD_CHUNK_SIZE` is the whole stream.
pub(crate) async fn read_first_chunk(
    data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; UPLOAD_PROBE_SIZE];
    let mut chunk_len = read_full_chunk(data, &mut buffer).await?;
    if chunk_len == UPLOAD_PROBE_SIZE {
        buffer.resize(UPLOAD_CHUNK_SIZE, 0);
        chunk_len += read_full_chunk(data, &mut buffer[UPLOAD_PROBE_SIZE..]).await?;
    }
    buffer.truncate(chunk_len);
    Ok(buffer)
}

// Sanitize object tag key/value components. Replace any non [A-Za-z0-9_.-]
// characters with '_'; that set is valid for both Azure blob index tags and
// S3 object tags.
pub(crate) fn sanitize_tag_component(input: &str) -> String {
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

/// Whether upload tagging is enabled. Disabled by default (tagging costs an
/// extra round-trip per upload on Azure, some S3-compatible stores do not
/// support it, and nothing here reads the tags back); enable via
/// KCI_STORAGE_ENABLE_UPLOAD_TAGS=1/true/yes when a backend lifecycle rule
/// needs the owner/retention tags.
fn upload_tags_enabled() -> bool {
    std::env::var("KCI_STORAGE_ENABLE_UPLOAD_TAGS")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Tags for a new upload: owner (when known) plus the optional configured
/// retention tag, sanitized. A backend lifecycle rule matching the retention
/// tag can then expire the object. Empty when tagging is disabled or there is
/// nothing to tag.
pub(crate) fn upload_tag_pairs(owner_email: Option<String>) -> Vec<(String, String)> {
    if !upload_tags_enabled() {
        return Vec::new();
    }
    tag_pairs(owner_email, crate::get_retention_tag())
}

fn tag_pairs(
    owner_email: Option<String>,
    retention: Option<(String, String)>,
) -> Vec<(String, String)> {
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

    if let Some((key, value)) = retention {
        let key = sanitize_tag_component(&key);
        let value = sanitize_tag_component(&value);
        if !key.is_empty() && !value.is_empty() {
            pairs.push((key, value));
        } else {
            debug_log!("Retention tag is empty after sanitization, skipping");
        }
    }
    pairs
}

/// A reader that fails on the first read, for upload error-path tests.
#[cfg(test)]
pub(crate) struct FailedRead;

#[cfg(test)]
impl tokio::io::AsyncRead for FailedRead {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("injected read error")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_pairs_are_sanitized() {
        assert!(tag_pairs(None, None).is_empty());
        assert_eq!(
            tag_pairs(
                Some("user@example.org".to_string()),
                Some(("retention".to_string(), "6 m".to_string()))
            ),
            vec![
                ("owner".to_string(), "user_example.org".to_string()),
                ("retention".to_string(), "6_m".to_string()),
            ]
        );
        assert_eq!(
            tag_pairs(Some(String::new()), Some((String::new(), "x".to_string()))),
            vec![("owner".to_string(), "_".to_string())]
        );
    }

    #[tokio::test]
    async fn first_chunk_is_whole_stream_below_chunk_size() {
        for size in [
            0,
            16,
            UPLOAD_PROBE_SIZE,
            UPLOAD_CHUNK_SIZE,
            UPLOAD_CHUNK_SIZE + 1,
        ] {
            let mut input = std::io::Cursor::new(vec![7u8; size]);
            let chunk = read_first_chunk(&mut input).await.unwrap();
            assert_eq!(chunk.len(), size.min(UPLOAD_CHUNK_SIZE));
        }
    }
}
