// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
use axum::http::{Method, StatusCode, Uri};
use object_store::memory::InMemory;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

#[test]
fn cache_locations_do_not_reuse_other_objects_or_legacy_entries() {
    crate::storcaching::block_on_with_counter_lock(async {
        let cache = tempfile::tempdir().unwrap();
        let root = cache.path().to_str().unwrap();
        crate::storcaching::prepare_cache_layout(root).unwrap();
        let builder = AmazonS3Builder::new().with_bucket_name("bucket");
        let backend = |builder: &AmazonS3Builder, prefix: &str| S3Backend {
            store: Arc::new(InMemory::new()),
            cache_namespace: cache_namespace(builder, prefix),
            prefix: prefix.to_string(),
            cache_dir: root.to_string(),
        };
        let original = backend(&builder, "prefix");
        original
            .write_streaming(
                "file",
                &mut std::io::Cursor::new(b"original"),
                "text/plain".into(),
                TagSet::default(),
            )
            .await
            .unwrap();
        assert!(original.get_file("file".into()).await.valid);

        // Same filename, different location with no object must be a miss.
        for changed in [
            backend(&builder, "other-prefix"),
            backend(&builder.clone().with_bucket_name("other-bucket"), "prefix"),
            backend(
                &builder.clone().with_endpoint("https://other.example"),
                "prefix",
            ),
            backend(
                &builder
                    .clone()
                    .with_config(AmazonS3ConfigKey::S3Endpoint, "https://service.example"),
                "prefix",
            ),
            backend(&builder.clone().with_region("other-region"), "prefix"),
            backend(
                &builder.clone().with_virtual_hosted_style_request(true),
                "prefix",
            ),
        ] {
            assert!(!changed.get_file("file".into()).await.valid);
            changed
                .write_streaming(
                    "file",
                    &mut std::io::Cursor::new(b"changed"),
                    "text/plain".into(),
                    TagSet::default(),
                )
                .await
                .unwrap();
            let mut received = changed.get_file("file".into()).await;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(received.file.as_mut().unwrap(), &mut bytes).unwrap();
            assert_eq!(bytes, b"changed");
        }
        assert!(matches!(
            original.get_file("file".into()).await.cache_state,
            CacheState::Cached
        ));

        // Both the legacy filename-only cache and the Azure namespace are ignored.
        for key in [
            "legacy".to_string(),
            objcache::scoped_key("azure", &["account", "container"], "azure"),
        ] {
            let body = futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"old"))]);
            assert!(
                objcache::store(root, "unused", &key, HeaderMap::new(), body)
                    .await
                    .valid
            );
        }
        assert!(!original.get_file("legacy".into()).await.valid);
        assert!(!original.get_file("azure".into()).await.valid);
    });
}

#[test]
fn cache_scope_is_unambiguous_and_ignores_credential_rotation() {
    assert_ne!(
        objcache::scoped_key("s3", &["a", "b/c"], "d"),
        objcache::scoped_key("s3", &["a/b", "c"], "d")
    );
    assert_ne!(
        objcache::scoped_key("s3", &["a"], "b"),
        objcache::scoped_key("azure", &["a"], "b")
    );
    let builder = AmazonS3Builder::new().with_bucket_name("bucket");
    assert_eq!(
        cache_namespace(&builder, "prefix"),
        cache_namespace(
            &builder
                .clone()
                .with_access_key_id("new-key")
                .with_secret_access_key("new-secret"),
            "prefix"
        )
    );
}

// Exercise the actual object_store HTTP protocol, including explicit DELETE
// aborts. Gates let tests cancel at precise lifecycle states without sleeps.
struct MockS3 {
    builder: AmazonS3Builder,
    endpoint: String,
    requests: mpsc::UnboundedReceiver<(Method, Uri)>,
    gate: Arc<Semaphore>,
    server: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    PauseInitiation,
    PauseCompletion,
    PauseFailedCompletion,
    FailPart,
    FailCompletion,
}

impl MockS3 {
    async fn new(mode: Mode) -> Self {
        let (sender, requests) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        let handler_gate = gate.clone();
        let app = axum::Router::new().fallback(move |method: Method, uri: Uri, _body: Bytes| {
            let sender = sender.clone();
            let gate = handler_gate.clone();
            async move {
                let _ = sender.send((method.clone(), uri.clone()));
                let initiating = method == Method::POST && uri.query() == Some("uploads=");
                let completing = method == Method::POST && !initiating;
                if (initiating && mode == Mode::PauseInitiation)
                    || (completing && matches!(mode, Mode::PauseCompletion | Mode::PauseFailedCompletion)) {
                    gate.acquire().await.unwrap().forget();
                }
                if (method == Method::PUT && mode == Mode::FailPart)
                    || (completing && matches!(mode, Mode::FailCompletion | Mode::PauseFailedCompletion)) {
                    return (StatusCode::FORBIDDEN, [("etag", "mock")], "");
                }
                let body = if initiating {
                    "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>file</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>"
                } else if completing {
                    "<CompleteMultipartUploadResult><Location>http://localhost/file</Location><Bucket>bucket</Bucket><Key>file</Key><ETag>mock</ETag></CompleteMultipartUploadResult>"
                } else { "" };
                let status = if method == Method::HEAD { StatusCode::NOT_FOUND } else { StatusCode::OK };
                (status, [("etag", "mock")], body)
            }
        }).layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let builder = AmazonS3Builder::new()
            .with_bucket_name("bucket")
            .with_endpoint(&endpoint)
            .with_allow_http(true)
            .with_skip_signature(true)
            .with_retry(object_store::RetryConfig {
                max_retries: 0,
                ..Default::default()
            });
        Self {
            builder,
            endpoint,
            requests,
            gate,
            server,
        }
    }

    fn store(&self) -> Arc<dyn ObjectStore> {
        Arc::new(self.builder.clone().build().unwrap())
    }

    async fn next(&mut self) -> (Method, Uri) {
        tokio::time::timeout(Duration::from_secs(5), self.requests.recv())
            .await
            .expect("expected S3 request")
            .expect("mock stopped")
    }

    async fn until(&mut self, expected: Method) -> Uri {
        loop {
            let (method, uri) = self.next().await;
            if method == expected {
                return uri;
            }
        }
    }
}

impl Drop for MockS3 {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn explicit_endpoint_overrides_service_endpoint_and_omission_preserves_it() {
    let mut configured = MockS3::new(Mode::Normal).await;
    let mut inherited = MockS3::new(Mode::Normal).await;
    // with_config is exactly how from_env imports AWS_ENDPOINT_URL_S3. Avoid
    // mutating process-global environment while the test suite runs in parallel.
    let env_builder = configured
        .builder
        .clone()
        .with_config("aws_endpoint_url_s3".parse().unwrap(), &inherited.endpoint);
    for endpoint in [None, Some(configured.endpoint.clone())] {
        let explicit = endpoint.is_some();
        let config = S3Config {
            bucket: "bucket".into(),
            endpoint,
            ..Default::default()
        };
        let store = configure_builder(env_builder.clone(), &config)
            .build()
            .unwrap();
        assert!(store.head(&Path::from("file")).await.is_err());
        let target = if explicit {
            &mut configured
        } else {
            &mut inherited
        };
        assert_eq!(target.until(Method::HEAD).await.path(), "/bucket/file");
    }
}

#[tokio::test]
async fn virtual_host_environment_survives_omission_and_explicit_values_win() {
    let mut mock = MockS3::new(Mode::Normal).await;
    let env_builder = mock
        .builder
        .clone()
        .with_config("aws_virtual_hosted_style_request".parse().unwrap(), "true");
    for (setting, expected_path) in [
        (None, "/file"),
        (Some(false), "/bucket/file"),
        (Some(true), "/file"),
    ] {
        let config = S3Config {
            bucket: "bucket".into(),
            virtual_hosted_style: setting,
            ..Default::default()
        };
        let store = configure_builder(env_builder.clone(), &config)
            .build()
            .unwrap();
        assert!(store.head(&Path::from("file")).await.is_err());
        assert_eq!(mock.until(Method::HEAD).await.path(), expected_path);
    }
    let config = S3Config {
        bucket: "bucket".into(),
        ..Default::default()
    };
    let store = configure_builder(mock.builder.clone(), &config)
        .build()
        .unwrap();
    assert!(store.head(&Path::from("file")).await.is_err());
    assert_eq!(mock.until(Method::HEAD).await.path(), "/bucket/file");
}

#[tokio::test]
async fn cancellation_during_initiation_or_streaming_aborts_upload() {
    for mode in [Mode::PauseInitiation, Mode::Normal] {
        let mut mock = MockS3::new(mode).await;
        let store = mock.store();
        let (reader, _keep_open) = tokio::io::duplex(1);
        let request = tokio::spawn(async move {
            let mut input = std::io::Cursor::new(vec![0; UPLOAD_CHUNK_SIZE]).chain(reader);
            upload_stream(
                store,
                &Path::from("file"),
                &mut input,
                "a/b".into(),
                TagSet::default(),
            )
            .await
        });
        assert_eq!(mock.until(Method::POST).await.query(), Some("uploads="));
        if mode == Mode::Normal {
            mock.until(Method::PUT).await;
        }
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        mock.gate.add_permits(1);
        let abort = mock.until(Method::DELETE).await;
        assert!(abort.query().unwrap().contains("uploadId=upload-1"));
    }
}

#[tokio::test]
async fn cancellation_during_completion_keeps_completion_owned() {
    for mode in [Mode::PauseCompletion, Mode::PauseFailedCompletion] {
        let mut mock = MockS3::new(mode).await;
        let store = mock.store();
        let worker_store = Arc::downgrade(&store);
        let request = tokio::spawn(async move {
            let mut input = std::io::Cursor::new(vec![0; UPLOAD_CHUNK_SIZE]);
            upload_stream(
                store,
                &Path::from("file"),
                &mut input,
                "a/b".into(),
                TagSet::default(),
            )
            .await
        });
        mock.until(Method::POST).await; // Initiation
        assert!(mock
            .until(Method::POST)
            .await
            .query()
            .unwrap()
            .contains("uploadId=upload-1"));
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        // The worker still owns completion after the caller has gone away.
        assert!(worker_store.upgrade().is_some());
        mock.gate.add_permits(1);
        if mode == Mode::PauseFailedCompletion {
            mock.until(Method::DELETE).await;
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while worker_store.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("upload worker did not finish cleanup");
    }
}

#[tokio::test]
async fn read_part_and_completion_errors_abort_upload() {
    for mode in [Mode::Normal, Mode::FailPart, Mode::FailCompletion] {
        let mut mock = MockS3::new(mode).await;
        let mut input: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if mode == Mode::Normal {
            Box::new(
                std::io::Cursor::new(vec![0; UPLOAD_CHUNK_SIZE])
                    .chain(crate::objupload::FailedRead),
            )
        } else {
            Box::new(std::io::Cursor::new(vec![0; UPLOAD_CHUNK_SIZE]))
        };
        assert!(upload_stream(
            mock.store(),
            &Path::from("file"),
            input.as_mut(),
            "a/b".into(),
            TagSet::default()
        )
        .await
        .is_err());
        assert!(mock
            .until(Method::DELETE)
            .await
            .query()
            .unwrap()
            .contains("uploadId=upload-1"));
    }
}
