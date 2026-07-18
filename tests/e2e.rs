// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
//
// End-to-end tests for kernelci-storage using the local storage driver.
// These tests start the actual server binary and exercise the HTTP API.

use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::blocking::multipart;
use serde::Serialize;
use serde_json::Value;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

const JWT_SECRET: &str = "test-secret-for-e2e-testing";
const TEST_EMAIL: &str = "test@kernelci.org";
const RESTRICTED_EMAIL: &str = "restricted@kernelci.org";

#[derive(Serialize)]
struct Claims {
    email: String,
}

/// Find an available TCP port
fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to ephemeral port");
    listener.local_addr().unwrap().port()
}

/// Generate a JWT token for the given email using the test secret
fn generate_token(email: &str) -> String {
    let key = EncodingKey::from_secret(JWT_SECRET.as_bytes());
    let claims = Claims {
        email: email.to_string(),
    };
    encode(&Header::default(), &claims, &key).unwrap()
}

fn build_tar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *content).unwrap();
        }
        builder.finish().unwrap();
    }
    archive
}

fn xz_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn build_raw_tar_archive(path: &str, content: &[u8]) -> Vec<u8> {
    fn write_octal_field(field: &mut [u8], value: u64) {
        let encoded = format!("{:0width$o}\0", value, width = field.len() - 1);
        field.copy_from_slice(encoded.as_bytes());
    }

    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    write_octal_field(&mut header[100..108], 0o644);
    write_octal_field(&mut header[108..116], 0);
    write_octal_field(&mut header[116..124], 0);
    write_octal_field(&mut header[124..136], content.len() as u64);
    write_octal_field(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
    let checksum_field = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(checksum_field.as_bytes());

    let mut archive = Vec::new();
    archive.extend_from_slice(&header);
    archive.extend_from_slice(content);
    let padding = (512 - (content.len() % 512)) % 512;
    archive.extend(std::iter::repeat(0).take(padding));
    archive.extend(std::iter::repeat(0).take(1024));
    archive
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

[download_challenge]
user_agents = ["challenge-browser"]
secret = "0123456789abcdef0123456789abcdef"
cookie_ttl_seconds = 600
ipv4_prefix_length = 24
ipv6_prefix_length = 64
fallback_bytes_per_second = 262144
secure_cookie = false

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

[retention]
tag_value = "6m"
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
            if let Ok(resp) = client
                .get(&self.base_url)
                .timeout(Duration::from_millis(200))
                .send()
            {
                if resp.status().is_success() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "Server did not become ready within 5 seconds on port {}",
            self.port
        );
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
    let resp = server.client().get(server.url("/")).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().unwrap(), "KernelCI Storage Server");
}

#[test]
fn test_checkauth_valid_token() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let resp = server
        .client()
        .get(server.url("/v1/checkauth"))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(
        body.contains("Authorized"),
        "Expected 'Authorized' in body, got: {}",
        body
    );
    assert!(
        body.contains(TEST_EMAIL),
        "Expected email in body, got: {}",
        body
    );
}

#[test]
fn test_checkauth_no_token() {
    let server = TestServer::start();
    let resp = server
        .client()
        .get(server.url("/v1/checkauth"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[test]
fn test_checkauth_invalid_token() {
    let server = TestServer::start();
    let resp = server
        .client()
        .get(server.url("/v1/checkauth"))
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
    let form = multipart::Form::new().text("path", "testdir").part(
        "file0",
        multipart::Part::bytes(file_content.to_vec())
            .file_name("hello.txt")
            .mime_str("text/plain")
            .unwrap(),
    );

    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "Upload failed: {:?}", resp.text());

    // Download
    let resp = client.get(server.url("/testdir/hello.txt")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().unwrap();
    assert_eq!(body.as_ref(), file_content);
}

#[test]
fn test_browser_download_challenge_cookie_and_fallback() {
    let server = TestServer::start();
    let artifact_dir = server.work_dir.path().join("storage/challenge");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("artifact.bin"), b"challenged download").unwrap();

    let client = server.client();
    let artifact_url = server.url("/challenge/artifact.bin");
    let challenged = client
        .get(&artifact_url)
        .header("User-Agent", "Challenge-Browser/1.0")
        .send()
        .unwrap();
    assert_eq!(challenged.status(), 200);
    assert!(challenged
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(challenged.text().unwrap().contains("Please wait"));

    let token_response = client
        .post(server.url("/v1/download-challenge"))
        .header("User-Agent", "Challenge-Browser/1.0")
        .send()
        .unwrap();
    assert_eq!(token_response.status(), 204);
    let set_cookie = token_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let cookie = set_cookie.split(';').next().unwrap();
    assert!(cookie.starts_with("kci-download="));

    let downloaded = client
        .get(&artifact_url)
        .header("User-Agent", "Challenge-Browser/1.0")
        .header("Cookie", cookie)
        .send()
        .unwrap();
    assert_eq!(downloaded.status(), 200);
    assert_eq!(downloaded.bytes().unwrap().as_ref(), b"challenged download");

    let fallback = client
        .get(format!("{artifact_url}?challenge_fallback=1"))
        .header("User-Agent", "Challenge-Browser/1.0")
        .send()
        .unwrap();
    assert_eq!(fallback.status(), 200);
    assert_eq!(
        fallback
            .headers()
            .get("x-accel-limit-rate")
            .unwrap()
            .to_str()
            .unwrap(),
        "262144"
    );
    assert_eq!(fallback.bytes().unwrap().as_ref(), b"challenged download");
}

#[test]
fn test_upload_via_legacy_endpoint() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"legacy upload test";
    let form = multipart::Form::new().text("path", "legacy").part(
        "file0",
        multipart::Part::bytes(file_content.to_vec())
            .file_name("test.bin")
            .mime_str("application/octet-stream")
            .unwrap(),
    );

    let resp = client
        .post(server.url("/upload"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify download works
    let resp = client.get(server.url("/legacy/test.bin")).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().unwrap().as_ref(), file_content);
}

#[test]
fn test_archive_upload_unpacks_files() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let archive = xz_compress(&build_tar_archive(&[
        ("omap4-droid-bionic-xt875.dtb", b"omap4 dtb"),
        ("nested/imx6ull-tarragon-micro.dtb", b"imx6 dtb"),
        ("rv1108-evb.dtb", b"rv1108 dtb"),
    ]));

    let form = multipart::Form::new()
        .text(
            "path",
            "kbuild-clang-21-arm-allmodconfig-6a3c1ef26de4dcc0f43c0656/dtbs",
        )
        .part(
            "archive",
            multipart::Part::bytes(archive)
                .file_name("dtbs.tar.xz")
                .mime_str("application/x-xz")
                .unwrap(),
        );

    let resp = client
        .post(server.url("/v1/archive"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Archive upload failed: {:?}",
        resp.text()
    );
    let body: Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["uploaded"], 3);
    assert_eq!(body["failed"], 0);

    let resp = client
        .get(server.url(
            "/kbuild-clang-21-arm-allmodconfig-6a3c1ef26de4dcc0f43c0656/dtbs/omap4-droid-bionic-xt875.dtb",
        ))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().unwrap().as_ref(), b"omap4 dtb");

    let resp = client
        .get(server.url(
            "/kbuild-clang-21-arm-allmodconfig-6a3c1ef26de4dcc0f43c0656/dtbs/nested/imx6ull-tarragon-micro.dtb",
        ))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().unwrap().as_ref(), b"imx6 dtb");
}

#[test]
fn test_archive_upload_rejects_path_traversal() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let archive = build_raw_tar_archive("../evil.dtb", b"evil");
    let form = multipart::Form::new().text("path", "safe-prefix").part(
        "archive",
        multipart::Part::bytes(archive)
            .file_name("evil.tar")
            .mime_str("application/x-tar")
            .unwrap(),
    );

    let resp = client
        .post(server.url("/v1/archive"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = client.get(server.url("/evil.dtb")).send().unwrap();
    assert_eq!(resp.status(), 404);
}

#[test]
fn test_upload_unauthorized() {
    let server = TestServer::start();
    let client = server.client();

    let form = multipart::Form::new().text("path", "testdir").part(
        "file0",
        multipart::Part::bytes(b"should fail".to_vec())
            .file_name("fail.txt")
            .mime_str("text/plain")
            .unwrap(),
    );

    let resp = client
        .post(server.url("/v1/file"))
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
    let form = multipart::Form::new().text("path", "other-dir").part(
        "file0",
        multipart::Part::bytes(b"should be forbidden".to_vec())
            .file_name("forbidden.txt")
            .mime_str("text/plain")
            .unwrap(),
    );

    let resp = client
        .post(server.url("/v1/file"))
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
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Upload should be allowed: {:?}",
        resp.text()
    );
}

#[test]
fn test_download_not_found() {
    let server = TestServer::start();
    let resp = server
        .client()
        .get(server.url("/nonexistent/file.txt"))
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
        let form = multipart::Form::new().text("path", path.to_string()).part(
            "file0",
            multipart::Part::bytes(content.as_bytes().to_vec())
                .file_name(name.to_string())
                .mime_str("text/plain")
                .unwrap(),
        );

        let resp = client
            .post(server.url("/v1/file"))
            .header("Authorization", format!("Bearer {}", token))
            .multipart(form)
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200, "Upload of {} failed", name);
    }

    // List files
    let resp = client.get(server.url("/v1/list")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(
        body.contains("list-test/file1.txt"),
        "Missing file1.txt in list: {}",
        body
    );
    assert!(
        body.contains("list-test/file2.txt"),
        "Missing file2.txt in list: {}",
        body
    );
    assert!(
        body.contains("list-test/sub/file3.txt"),
        "Missing file3.txt in list: {}",
        body
    );
}

#[test]
fn test_range_request() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let file_content = b"0123456789ABCDEF";

    // Upload
    let form = multipart::Form::new().text("path", "range-test").part(
        "file0",
        multipart::Part::bytes(file_content.to_vec())
            .file_name("data.bin")
            .mime_str("application/octet-stream")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Range request: bytes 5 onwards
    let resp = client
        .get(server.url("/range-test/data.bin"))
        .header("Range", "bytes=5-")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        206,
        "Expected 206 Partial Content, got {}",
        resp.status()
    );
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
    let form = multipart::Form::new().text("path", "head-test").part(
        "file0",
        multipart::Part::bytes(file_content.to_vec())
            .file_name("file.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // HEAD request
    let resp = client
        .head(server.url("/head-test/file.txt"))
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
    let form = multipart::Form::new().text("path", "etag-test").part(
        "file0",
        multipart::Part::bytes(file_content.to_vec())
            .file_name("file.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // First GET to obtain ETag
    let resp = client
        .get(server.url("/etag-test/file.txt"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag = resp
        .headers()
        .get("etag")
        .map(|v| v.to_str().unwrap().to_string());

    if let Some(etag) = etag {
        // Conditional GET with If-None-Match
        let resp = client
            .get(server.url("/etag-test/file.txt"))
            .header("If-None-Match", &etag)
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            304,
            "Expected 304 Not Modified, got {}",
            resp.status()
        );
    }
}

#[test]
fn test_path_traversal_rejected() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let form = multipart::Form::new().text("path", "../etc").part(
        "file0",
        multipart::Part::bytes(b"evil".to_vec())
            .file_name("passwd")
            .mime_str("text/plain")
            .unwrap(),
    );

    let resp = client
        .post(server.url("/v1/file"))
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
    let form = multipart::Form::new().text("path", "dup-test").part(
        "file0",
        multipart::Part::bytes(b"first upload".to_vec())
            .file_name("same.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second upload to same path - overwrites the file
    let form = multipart::Form::new().text("path", "dup-test").part(
        "file0",
        multipart::Part::bytes(b"second upload".to_vec())
            .file_name("same.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "Re-upload should succeed (overwrite)");

    // Verify the new content
    let resp = client.get(server.url("/dup-test/same.txt")).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().unwrap().as_ref(), b"second upload");
}

#[test]
fn test_metrics_endpoint() {
    let server = TestServer::start();
    let resp = server.client().get(server.url("/metrics")).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(
        body.contains("storage_free_space") || body.contains("storage_total_space"),
        "Metrics should contain disk space info"
    );
}

#[test]
fn test_content_type_preserved() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    // Upload a .json file
    let form = multipart::Form::new().text("path", "ctype-test").part(
        "file0",
        multipart::Part::bytes(b"{\"key\": \"value\"}".to_vec())
            .file_name("data.json")
            .mime_str("application/json")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Download and check content-type
    let resp = client
        .get(server.url("/ctype-test/data.json"))
        .send()
        .unwrap();
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
fn test_retention_and_owner_tags_in_metadata() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    let form = multipart::Form::new().text("path", "retention-test").part(
        "file0",
        multipart::Part::bytes(b"retention tag test".to_vec())
            .file_name("tagged.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The metadata sidecar must carry the configured retention tag alongside
    // the owner tag (sidecar filenames are path hashes, so scan the dir)
    let metadata_dir = server.work_dir.path().join("storage").join(".metadata");
    let mut found = false;
    for entry in std::fs::read_dir(&metadata_dir).unwrap().flatten() {
        let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
        if content.contains("tag-retention:6m") {
            assert!(
                content.contains(&format!("tag-owner:{}", TEST_EMAIL)),
                "Owner tag missing from metadata: {}",
                content
            );
            found = true;
        }
    }
    assert!(found, "No metadata file with retention tag found");
}

#[test]
fn test_large_file_upload() {
    let server = TestServer::start();
    let token = generate_token(TEST_EMAIL);
    let client = server.client();

    // Create a 1MB file
    let file_content: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let expected_len = file_content.len();

    let form = multipart::Form::new().text("path", "large-test").part(
        "file0",
        multipart::Part::bytes(file_content)
            .file_name("large.bin")
            .mime_str("application/octet-stream")
            .unwrap(),
    );
    let resp = client
        .post(server.url("/v1/file"))
        .header("Authorization", format!("Bearer {}", token))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Download and verify size
    let resp = client
        .get(server.url("/large-test/large.bin"))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), expected_len, "Downloaded file size mismatch");
}
