// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
//
// End-to-end tests for kernelci-storage using the local storage driver.
// These tests start the actual server binary and exercise the HTTP API.

use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use reqwest::blocking::multipart;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

const JWT_SECRET: &str = "test-secret-for-e2e-testing";
const TEST_EMAIL: &str = "test@kernelci.org";
const RESTRICTED_EMAIL: &str = "restricted@kernelci.org";

/// Find an available TCP port
fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to ephemeral port");
    listener.local_addr().unwrap().port()
}

/// Generate a JWT token for the given email using the test secret
fn generate_token(email: &str) -> String {
    let key: Hmac<Sha256> = Hmac::new_from_slice(JWT_SECRET.as_bytes()).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("email".to_string(), email.to_string());
    claims.sign_with_key(&key).unwrap()
}

/// Test server handle - kills the server process on drop
#[allow(dead_code)]
struct TestServer {
    process: Child,
    port: u16,
    base_url: String,
    work_dir: tempfile::TempDir,
}

impl TestServer {
    fn start() -> Self {
        let work_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
        let port = get_free_port();

        // Create storage directory
        let storage_path = work_dir.path().join("storage");
        std::fs::create_dir_all(&storage_path).unwrap();

        // Write test config
        let config_path = work_dir.path().join("config.toml");
        let config_content = format!(
            r#"driver="local"
jwt_secret="{JWT_SECRET}"

[local]
storage_path="{}"

[[users]]
name = "{TEST_EMAIL}"
prefixes = [""]

[[users]]
name = "{RESTRICTED_EMAIL}"
prefixes = ["restricted-area"]

[cache]
cleanup_chunk_size=100000
"#,
            storage_path.display()
        );
        std::fs::write(&config_path, &config_content).unwrap();

        // Build the binary first (reuse cached build)
        let build_status = Command::new("cargo")
            .args(["build"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("Failed to build");
        assert!(build_status.success(), "cargo build failed");

        // Find the binary
        let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join("kernelci-storage");

        // Start the server
        let process = Command::new(&binary)
            .args([
                "--files-directory",
                work_dir.path().to_str().unwrap(),
                "--config-file",
                config_path.to_str().unwrap(),
            ])
            .env("KCI_STORAGE_PORT", port.to_string())
            .env("KCI_STORAGE_CONFIG", config_path.to_str().unwrap())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to start server");

        let server = TestServer {
            process,
            port,
            base_url: format!("http://127.0.0.1:{}", port),
            work_dir,
        };

        // Wait for server to be ready
        server.wait_until_ready();
        server
    }

    fn wait_until_ready(&self) {
        let client = reqwest::blocking::Client::new();
        for _ in 0..50 {
            if let Ok(resp) = client.get(&self.base_url).timeout(Duration::from_millis(200)).send() {
                if resp.status().is_success() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("Server did not become ready within 5 seconds on port {}", self.port);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn client(&self) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

// --- Test Cases ---

#[test]
fn test_root_endpoint() {
    let server = TestServer::start();
    let resp = server.client().get(&server.url("/")).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().unwrap(), "KernelCI Storage Server");
}

#[test]
fn test_checkauth_valid_token() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let resp = server
        .client()
        .get(&server.url("/v1/checkauth"))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(body.contains("Authorized"), "Expected 'Authorized' in body, got: {}", body);
    assert!(body.contains(TEST_EMAIL), "Expected email in body, got: {}", body);
}

#[test]
fn test_checkauth_no_token() {
    let server = TestServer::start();
    let resp = server
        .client()
        .get(&server.url("/v1/checkauth"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[test]
fn test_checkauth_invalid_token() {
    let server = TestServer::start();
    let resp = server
        .client()
        .get(&server.url("/v1/checkauth"))
        .header("Authorization", "Bearer invalid-token-value")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[test]
fn test_upload_and_download() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"Hello, KernelCI storage e2e test!";

    // Upload
    let form = multipart::Form::new()
        .text("path", "testdir")
        .part(
            "file0",
            multipart::Part::bytes(file_content.to_vec())
                .file_name("hello.txt")
                .mime_str("text/plain")
                .unwrap(),
        );

    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "Upload failed: {:?}", resp.text());

    // Download
    let resp = client.get(&server.url("/testdir/hello.txt")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().unwrap();
    assert_eq!(body.as_ref(), file_content);
}

#[test]
fn test_upload_via_legacy_endpoint() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"legacy upload test";
    let form = multipart::Form::new()
        .text("path", "legacy")
        .part(
            "file0",
            multipart::Part::bytes(file_content.to_vec())
                .file_name("test.bin")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    let resp = client
        .post(&server.url("/upload"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify download works
    let resp = client.get(&server.url("/legacy/test.bin")).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().unwrap().as_ref(), file_content);
}

#[test]
fn test_upload_unauthorized() {
    let server = TestServer::start();
    let client = server.client();

    let form = multipart::Form::new()
        .text("path", "testdir")
        .part(
            "file0",
            multipart::Part::bytes(b"should fail".to_vec())
                .file_name("fail.txt")
                .mime_str("text/plain")
                .unwrap(),
        );

    let resp = client
        .post(&server.url("/v1/file"))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[test]
fn test_upload_permission_denied() {
    let server = TestServer::start();
    let token = generate_token(RESTRICTED_EMAIL);
    let client = server.client();

    // restricted@kernelci.org can only upload to "restricted-area" prefix
    let form = multipart::Form::new()
        .text("path", "other-dir")
        .part(
            "file0",
            multipart::Part::bytes(b"should be forbidden".to_vec())
                .file_name("forbidden.txt")
                .mime_str("text/plain")
                .unwrap(),
        );

    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "Expected 403, got: {}", resp.status());
}

#[test]
fn test_upload_permission_allowed_prefix() {
    let server = TestServer::start();
    let token = generate_token(RESTRICTED_EMAIL);
    let client = server.client();

    // restricted@kernelci.org can upload to "restricted-area" prefix
    let form = multipart::Form::new()
        .text("path", "restricted-area/subdir")
        .part(
            "file0",
            multipart::Part::bytes(b"allowed content".to_vec())
                .file_name("allowed.txt")
                .mime_str("text/plain")
                .unwrap(),
        );

    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "Upload should be allowed: {:?}", resp.text());
}

#[test]
fn test_download_not_found() {
    let server = TestServer::start();
    let resp = server
        .client()
        .get(&server.url("/nonexistent/file.txt"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[test]
fn test_list_files() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    // Upload a couple of files
    for (path, name, content) in [
        ("list-test", "file1.txt", "content1"),
        ("list-test", "file2.txt", "content2"),
        ("list-test/sub", "file3.txt", "content3"),
    ] {
        let form = multipart::Form::new()
            .text("path", path.to_string())
            .part(
                "file0",
                multipart::Part::bytes(content.as_bytes().to_vec())
                    .file_name(name.to_string())
                    .mime_str("text/plain")
                    .unwrap(),
            );

        let resp = client
            .post(&server.url("/v1/file"))
            .header("Authorization", format!("Bearer {}", token))
            .multipart(form)
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200, "Upload of {} failed", name);
    }

    // List files
    let resp = client.get(&server.url("/v1/list")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(body.contains("list-test/file1.txt"), "Missing file1.txt in list: {}", body);
    assert!(body.contains("list-test/file2.txt"), "Missing file2.txt in list: {}", body);
    assert!(body.contains("list-test/sub/file3.txt"), "Missing file3.txt in list: {}", body);
}

#[test]
fn test_range_request() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"0123456789ABCDEF";

    // Upload
    let form = multipart::Form::new()
        .text("path", "range-test")
        .part(
            "file0",
            multipart::Part::bytes(file_content.to_vec())
                .file_name("data.bin")
                .mime_str("application/octet-stream")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Range request: bytes 5 onwards
    let resp = client
        .get(&server.url("/range-test/data.bin"))
        .header("Range", "bytes=5-")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 206, "Expected 206 Partial Content, got {}", resp.status());
    let body = resp.bytes().unwrap();
    assert_eq!(body.as_ref(), &file_content[5..]);
}

#[test]
fn test_head_request() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"head request test content";

    // Upload
    let form = multipart::Form::new()
        .text("path", "head-test")
        .part(
            "file0",
            multipart::Part::bytes(file_content.to_vec())
                .file_name("file.txt")
                .mime_str("text/plain")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // HEAD request
    let resp = client
        .head(&server.url("/head-test/file.txt"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    // HEAD should not return body but should have headers
    let body = resp.bytes().unwrap();
    assert!(body.is_empty(), "HEAD response should have empty body");
}

#[test]
fn test_conditional_request_etag() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"etag test content";

    // Upload
    let form = multipart::Form::new()
        .text("path", "etag-test")
        .part(
            "file0",
            multipart::Part::bytes(file_content.to_vec())
                .file_name("file.txt")
                .mime_str("text/plain")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // First GET to obtain ETag
    let resp = client
        .get(&server.url("/etag-test/file.txt"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag = resp.headers().get("etag").map(|v| v.to_str().unwrap().to_string());

    if let Some(etag) = etag {
        // Conditional GET with If-None-Match
        let resp = client
            .get(&server.url("/etag-test/file.txt"))
            .header("If-None-Match", &etag)
            .send()
            .unwrap();
        assert_eq!(resp.status(), 304, "Expected 304 Not Modified, got {}", resp.status());
    }
}

#[test]
fn test_path_traversal_rejected() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let form = multipart::Form::new()
        .text("path", "../etc")
        .part(
            "file0",
            multipart::Part::bytes(b"evil".to_vec())
                .file_name("passwd")
                .mime_str("text/plain")
                .unwrap(),
        );

    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 400, "Path traversal should be rejected");
}

#[test]
fn test_upload_overwrite() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    // First upload
    let form = multipart::Form::new()
        .text("path", "dup-test")
        .part(
            "file0",
            multipart::Part::bytes(b"first upload".to_vec())
                .file_name("same.txt")
                .mime_str("text/plain")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second upload to same path - overwrites the file
    let form = multipart::Form::new()
        .text("path", "dup-test")
        .part(
            "file0",
            multipart::Part::bytes(b"second upload".to_vec())
                .file_name("same.txt")
                .mime_str("text/plain")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "Re-upload should succeed (overwrite)");

    // Verify the new content
    let resp = client.get(&server.url("/dup-test/same.txt")).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().unwrap().as_ref(), b"second upload");
}

#[test]
fn test_metrics_endpoint() {
    let server = TestServer::start();
    let resp = server.client().get(&server.url("/metrics")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(body.contains("storage_free_space") || body.contains("storage_total_space"),
        "Metrics should contain disk space info");
}

#[test]
fn test_content_type_preserved() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    // Upload a .json file
    let form = multipart::Form::new()
        .text("path", "ctype-test")
        .part(
            "file0",
            multipart::Part::bytes(b"{\"key\": \"value\"}".to_vec())
                .file_name("data.json")
                .mime_str("application/json")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Download and check content-type
    let resp = client.get(&server.url("/ctype-test/data.json")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    // The server uses heuristic_filetype or stored content-type
    assert!(
        content_type.contains("json") || content_type.contains("octet-stream"),
        "Unexpected content-type: {}",
        content_type
    );
}

#[test]
fn test_large_file_upload() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    // Create a 1MB file
    let file_content: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let expected_len = file_content.len();

    let form = multipart::Form::new()
        .text("path", "large-test")
        .part(
            "file0",
            multipart::Part::bytes(file_content)
                .file_name("large.bin")
                .mime_str("application/octet-stream")
                .unwrap(),
        );
    let resp = client
        .post(&server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Download and verify size
    let resp = client.get(&server.url("/large-test/large.bin")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), expected_len, "Downloaded file size mismatch");
}
