// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024-2025 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>
/*
   KernelCI Storage Server

   This is a simple storage server that supports file upload and download, with token based authentication.
   It supports multiple backends, currently only Azure Blob is supported, to provide user transparent storage.
   It caches the files in a local directory and serves them from there.
   Range requests are supported, but only for start offset, end limit is not implemented yet.
*/

mod azure;
mod local;
#[macro_use]
mod logging;
mod storcaching;
mod storjwt;

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, OriginalUri, Path, State},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use async_trait::async_trait;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use headers::HeaderMap;
use std::path;
use std::sync::OnceLock;
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use std::{collections::HashMap, sync::Arc};
use std::pin::Pin;
use std::task::{Context, Poll};
use sysinfo::Disks;
use tokio::sync::{RwLock, Semaphore};
use tokio_util::io::ReaderStream;
use toml::Table;
use tower::ServiceBuilder;
use futures::Future;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "./", help = "Directory to store files")]
    files_directory: String,

    #[clap(
        short,
        long,
        default_value = "./ssl",
        help = "Directory with cert.pem and key.pem"
    )]
    ssl_directory: String,

    #[clap(
        short,
        long,
        default_value = "./config.toml",
        help = "Config file, relative to files_directory"
    )]
    config_file: String,

    #[clap(short, long, default_value = "false", help = "Generate JWT secret")]
    generate_jwt_secret: bool,

    #[clap(long, default_value = "", help = "Generate JWT token for email")]
    generate_jwt_token: String,

    #[clap(short, long, action = clap::ArgAction::SetTrue, help = "Enable verbose logging")]
    verbose: bool,
}

static ARGS: OnceLock<Args> = OnceLock::new();

fn get_args() -> &'static Args {
    ARGS.get_or_init(|| Args::parse())
}

// const names for last-modified and etag in lowercase
const LAST_MODIFIED: &str = "last-modified";
const ETAG: &str = "etag";
const CONTENT_TYPE: &str = "content-type";

type FileSemaphores = Arc<RwLock<HashMap<String, Arc<Semaphore>>>>;

#[derive(Clone)]
struct AppState {
    file_locks: FileSemaphores,
}

async fn get_or_create_semaphore(locks: &FileSemaphores, filename: &str) -> Arc<Semaphore> {
    let mut map = locks.write().await;
    map.entry(filename.to_string())
        .or_insert_with(|| Arc::new(Semaphore::new(1)))
        .clone()
}

struct ReceivedFile {
    original_filename: String,
    cached_filename: String,
    headers: HeaderMap,
    valid: bool,
}

// Wrapper to convert Multipart Field into AsyncRead
struct FieldStream<'a> {
    field: axum::extract::multipart::Field<'a>,
    buffer: Option<Bytes>,
    offset: usize,
}

impl<'a> FieldStream<'a> {
    fn new(field: axum::extract::multipart::Field<'a>) -> Self {
        FieldStream {
            field,
            buffer: None,
            offset: 0,
        }
    }
}

impl<'a> tokio::io::AsyncRead for FieldStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If we have buffered data, copy it first
        if let Some(buffer) = &this.buffer {
            if this.offset < buffer.len() {
                let remaining = &buffer[this.offset..];
                let to_copy = std::cmp::min(remaining.len(), buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                this.offset += to_copy;

                if this.offset >= buffer.len() {
                    this.buffer = None;
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
        }

        // Try to get next chunk from field
        let fut = this.field.chunk();
        tokio::pin!(fut);

        match fut.poll(cx) {
            Poll::Ready(Ok(Some(chunk))) => {
                let to_copy = std::cmp::min(chunk.len(), buf.remaining());
                buf.put_slice(&chunk[..to_copy]);

                if to_copy < chunk.len() {
                    // Store remaining data for next read
                    this.buffer = Some(chunk);
                    this.offset = to_copy;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => {
                // EOF
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait]
trait Driver: Send + Sync {
    fn write_file(
        &self,
        filename: String,
        data: Vec<u8>,
        cont_type: String,
        owner_email: Option<String>,
    ) -> String;
    async fn write_file_streaming(
        &self,
        filename: String,
        data: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        cont_type: String,
        owner_email: Option<String>,
    ) -> (String, usize);
    fn get_file(&self, filename: String) -> ReceivedFile;
    fn tag_file(
        &self,
        filename: String,
        user_tags: Vec<(String, String)>,
    ) -> Result<String, String>;
    fn list_files(&self, directory: String) -> Vec<String>;
}

fn init_driver(driver_type: &str) -> Box<dyn Driver> {
    let driver: Box<dyn Driver> = match driver_type {
        "azure" => Box::new(azure::AzureDriver::new()),
        "local" => Box::new(local::LocalDriver::new()),
        //"google" => Box::new(google::GoogleDriver::new()),
        _ => {
            eprintln!("Unknown driver type: {}", driver_type);
            std::process::exit(1);
        }
    };
    driver
}

pub fn get_config_content() -> String {
    let args = get_args();
    let mut cfg_file = PathBuf::from(&args.config_file);
    if let Ok(cfg_file_env) = std::env::var("KCI_STORAGE_CONFIG") {
        cfg_file = PathBuf::from(&cfg_file_env);
    }

    std::fs::read_to_string(&cfg_file).unwrap()
}

/// Get driver type from config.toml, defaults to "azure" for backward compatibility
fn get_driver_type() -> String {
    let cfg_content = get_config_content();
    let cfg: Table = toml::from_str(&cfg_content).unwrap();

    cfg.get("driver")
        .and_then(|v| v.as_str())
        .unwrap_or("azure")
        .to_string()
}

fn client_ip_from_headers(headers: &HeaderMap, fallback: SocketAddr) -> String {
    if let Some(forwarded_for) = headers
        .get("X-Forwarded-For")
        .and_then(|value| value.to_str().ok())
    {
        if let Some(first_ip) = forwarded_for
            .split(',')
            .map(|part| part.trim())
            .find(|part| !part.is_empty())
        {
            return first_ip.to_string();
        }
    }

    if let Some(forwarded) = headers
        .get("Forwarded")
        .and_then(|value| value.to_str().ok())
    {
        for entry in forwarded.split(',') {
            for directive in entry.split(';') {
                let directive = directive.trim();
                if let Some(value) = directive.strip_prefix("for=") {
                    let cleaned = value.trim_matches('"');
                    if !cleaned.is_empty() {
                        return cleaned.to_string();
                    }
                }
            }
        }
    }

    fallback.ip().to_string()
}

/// Initial variables configuration and checks
async fn initial_setup() -> Option<RustlsConfig> {
    let cache_dir = "cache";
    let download_dir = "download";
    let args = get_args();

    if args.generate_jwt_secret {
        storjwt::generate_jwt_secret();
        std::process::exit(0);
    }

    if !args.generate_jwt_token.is_empty() {
        let token_r = storjwt::generate_jwt_token(&args.generate_jwt_token);
        let token = match token_r {
            Ok(token) => token,
            Err(e) => {
                eprintln!("Error generating JWT token: {}", e);
                std::process::exit(1);
            }
        };
        println!("JWT token: {}", token);
        std::process::exit(0);
    }

    if let Err(e) = std::env::set_current_dir(&args.files_directory) {
        eprintln!("Error changing directory: {}", e);
        std::process::exit(1);
    }

    if !std::path::Path::new(cache_dir).exists() {
        std::fs::create_dir(cache_dir).unwrap();
    }

    let _validation = tokio::spawn(storcaching::validate_cache(cache_dir.to_string()));
    let _handle = tokio::spawn(storcaching::cache_loop(cache_dir));

    if !std::path::Path::new(download_dir).exists() {
        std::fs::create_dir(download_dir).unwrap();
    }

    let cfg_file: PathBuf;
    // is ENV KCI_STORAGE_CONFIG set?
    if let Ok(cfg_file_env) = std::env::var("KCI_STORAGE_CONFIG") {
        cfg_file = PathBuf::from(&cfg_file_env);
        debug_log!("Using config file from ENV: {}", cfg_file.display());
    } else {
        cfg_file = PathBuf::from(&args.config_file);
        debug_log!("Using config file from args: {}", cfg_file.display());
    }

    if !cfg_file.exists() {
        eprintln!("Config file {} does not exist", &args.config_file);
        std::process::exit(1);
    }

    let config = RustlsConfig::from_pem_file(
        PathBuf::from(&args.ssl_directory).join("cert.pem"),
        PathBuf::from(&args.ssl_directory).join("key.pem"),
    )
    .await;
    match config {
        Ok(tlsconf) => {
            debug_log!("TLS config loaded, HTTPS mode enabled");
            Some(tlsconf)
        }
        Err(e) => {
            eprintln!("TLS config error: {:?}, switching to plain HTTP", e);
            None
        }
    }
}

async fn ax_metrics() -> (StatusCode, String) {
    /*
    Prometheus metrics:
    storage_files_cached NNN
    storage_free_space NNN
    */
    let mut metrics = String::new();
    // prometehus header
    metrics.push_str("# HELP storage_free_space Free space on the disk\n");
    metrics.push_str("# TYPE storage_free_space gauge\n");
    metrics.push_str("# HELP storage_total_space Total space on the disk\n");
    metrics.push_str("# TYPE storage_total_space gauge\n");
    let hostname = "kernelci-storage".to_string();

    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        // if mount_point is not / and not /workdir, skip it
        // Docker :(
        let mount_point = disk.mount_point().to_string_lossy();
        if mount_point != "/" && mount_point != "/workdir" {
            continue;
        }
        // name, mount_point, total_space, available_space
        let tag_diskname = disk.name().to_string_lossy();
        let tag_total_space = disk.total_space();
        let tag_available_space = disk.available_space();

        metrics.push_str(&format!(
            "storage_free_space {{hostname=\"{}\", diskname=\"{}\", mount_point=\"{}\"}} {}\n",
            hostname, tag_diskname, mount_point, tag_available_space
        ));
        metrics.push_str(&format!(
            "storage_total_space {{hostname=\"{}\", diskname=\"{}\", mount_point=\"{}\"}} {}\n",
            hostname, tag_diskname, mount_point, tag_total_space
        ));
    }
    (StatusCode::OK, metrics)
}

#[tokio::main]
async fn main() {
    logging::init(get_args().verbose);
    tracing_subscriber::fmt::init();
    let tlscfg = initial_setup().await;
    let port = 3000;
    let state = AppState {
        file_locks: Arc::new(RwLock::new(HashMap::new())),
    };
    debug_log!("Starting server, tls: {:?}", tlscfg);

    // Supported endpoints:
    // GET / - root
    // GET /v1/checkauth - check if the token is correct
    // POST /v1/file and /upload - upload file
    // GET /*filepath - get file
    let app = Router::new()
        .route("/", get(root))
        .route("/favicon.ico", get(get_favicon))
        .route("/v1/checkauth", get(ax_check_auth))
        .route("/v1/file", post(ax_post_file))
        .route("/upload", post(ax_post_file))
        .route("/*filepath", get(ax_get_file))
        .route("/v1/list", get(ax_list_files))
        .route("/metrics", get(ax_metrics))
        .layer(ServiceBuilder::new().layer(DefaultBodyLimit::max(1024 * 1024 * 1024 * 4)))
        .with_state(state);

    /*
            .layer(SecureClientIpSource::ConnectInfo.into_extension())
            .layer(DefaultBodyLimit::max(1024 * 1024 * 1024 * 4));
    */
    if let Some(tlscfg) = tlscfg {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        //            .serve(app.into_make_service())
        axum_server::bind_rustls(addr, tlscfg)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        //let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        //axum::serve(listener, app).await.unwrap();
        axum_server::bind("0.0.0.0:3000".parse().unwrap())
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    }
}

async fn root() -> &'static str {
    "KernelCI Storage Server"
}

/// Redirect favicon.ico to https://kernelci.org/favicon.ico
async fn get_favicon() -> (StatusCode, &'static str) {
    (
        StatusCode::MOVED_PERMANENTLY,
        "https://kernelci.org/favicon.ico",
    )
}

/// Check if the Authorization header is present and if the token is correct    
/// Test it by: curl -X GET http://localhost:3000/v1/checkauth -H "Authorization: Bearer SuperSecretToken"
async fn ax_check_auth(headers: HeaderMap) -> (StatusCode, String) {
    let message = verify_auth_hdr(&headers);

    match message {
        Ok(email) => {
            let message = format!("Authorized: {}", email);
            debug_log!("Authorized: {}", email);
            (StatusCode::OK, message)
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
    }
}

// Guess content type based on filename (extension)
fn heuristic_filetype(filename: String) -> String {
    let ext = filename.split(".").last();
    let extension = ext.unwrap_or("bin");

    match extension {
        "bin" => "application/octet-stream".to_string(),
        "txt" => "text/plain".to_string(),
        "gz" => "application/gzip".to_string(),
        "tar" => "application/x-tar".to_string(),
        "zip" => "application/zip".to_string(),
        "tgz" => "application/x-gzip".to_string(),
        "log" => "text/plain".to_string(),
        "xz" => "application/x-xz".to_string(),
        "lz" => "application/x-lzip".to_string(),
        "json" => "application/json".to_string(),
        &_ => "application/octet-stream".to_string(),
    }
}

/*
Example config.toml section:

[users]
[users.alice]
prefixes = ["/alice"]
[users.bob]
prefixes = ["/bob"]
[users.admin]
prefixes = [""]
*/

fn validate_path(path: &str) -> Result<(), String> {
    if path.contains("..") {
        return Err("Path traversal detected".to_string());
    }
    Ok(())
}

fn verify_upload_permissions(owner: &str, path: &str) -> Result<(), String> {
    let cfg_content = get_config_content();
    let cfg: Table = toml::from_str(&cfg_content).unwrap();
    let users_r = cfg.get("users");
    let users = match users_r {
        Some(users) => users,
        None => {
            debug_log!("No users section in config.toml, ignoring upload path restriction");
            return Ok(());
        }
    };
    let users_vec = users.as_array().unwrap();
    for user in users_vec {
        let user_name = user.get("name").unwrap().as_str().unwrap();
        let user_prefixes = user.get("prefixes").unwrap();
        let user_prefixes_vec = user_prefixes.as_array().unwrap();
        for prefix_value in user_prefixes_vec {
            let prefix = prefix_value.as_str().unwrap();
            if (path.starts_with(prefix) || prefix.is_empty()) && user_name == owner {
                return Ok(());
            }
        }
    }
    Err(format!(
        "User {} has no upload permissions for path {}",
        owner, path
    ))
}

/*
    Upload file from user to remote storage
    TBD: Store file in cache as well?

    curl -X POST http://localhost:3000/v1/file -H "Authorization Bearer SuperSecretToken" -F "filename=@test.bin"

    This function will check if the Authorization header is present and if the token is correct
    If the token is correct, it will write the content of the file to the server
*/
async fn ax_post_file(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> (StatusCode, Vec<u8>) {
    // call check_auth
    let message = verify_auth_hdr(&headers);
    let owner = match message {
        Ok(owner) => owner,
        Err(_) => return (StatusCode::UNAUTHORIZED, Vec::new()),
    };
    debug_log!("Authorized");

    /* 100-continue Expect is broken, quite hard to fix in axum */
    /*
    if let Some(expect) = headers.get("Expect") {
        println!("Expect: {:?}", expect);
        if expect == "100-continue" {
            return (StatusCode::CONTINUE, Vec::new());
        }
    }
    */

    debug_log!("Uploading file");
    let mut path: String = "".to_string();
    let mut file0_filename: String = "".to_string();
    let mut upload_result: Option<(StatusCode, Vec<u8>)> = None;
    let mut buffered_file: Option<tempfile::NamedTempFile> = None;

    while let Some(field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(e) => {
            eprintln!("Error reading multipart field: {:?}", e);
            return (StatusCode::BAD_REQUEST, b"Malformed multipart request".to_vec());
        }
    } {
        let name = match field.name() {
            Some(name) => name.to_string(),
            None => continue,
        };
        let filename = field.file_name().map(|f| f.to_string());

        if name == "path" {
            let data = field.bytes().await;
            match data {
                Ok(data) => {
                    path = String::from_utf8(data.to_vec()).unwrap();
                    debug_log!("Field {}: path = {}", name, path);
                }
                Err(e) => {
                    eprintln!("Error reading path field: {:?}", e);
                    return (StatusCode::BAD_REQUEST, Vec::new());
                }
            }
        } else if name == "file0" {
            match filename {
                Some(fname) => {
                    file0_filename = fname.to_string();

                    if path.is_empty() {
                        // BUFFERED PATH: file0 arrived before path, buffer to temp file
                        debug_log!("file0 arrived before path, buffering to temp file");
                        let tmp = match tempfile::NamedTempFile::new() {
                            Ok(f) => f,
                            Err(e) => {
                                eprintln!("Failed to create temp file: {:?}", e);
                                upload_result = Some((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to create temp file".to_string().into_bytes(),
                                ));
                                break;
                            }
                        };
                        let tmp_path = tmp.path().to_path_buf();
                        let mut async_file = match tokio::fs::File::create(&tmp_path).await {
                            Ok(f) => f,
                            Err(e) => {
                                eprintln!("Failed to open temp file for writing: {:?}", e);
                                upload_result = Some((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to open temp file".to_string().into_bytes(),
                                ));
                                break;
                            }
                        };
                        let mut field_stream = FieldStream::new(field);
                        let mut buf = [0u8; 64 * 1024];
                        loop {
                            use tokio::io::AsyncReadExt;
                            let n = match field_stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(e) => {
                                    eprintln!("Error reading file0 field: {:?}", e);
                                    upload_result = Some((
                                        StatusCode::BAD_REQUEST,
                                        "Error reading file data".to_string().into_bytes(),
                                    ));
                                    break;
                                }
                            };
                            if let Err(e) = async_file.write_all(&buf[..n]).await {
                                eprintln!("Error writing temp file: {:?}", e);
                                upload_result = Some((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Error writing temp file".to_string().into_bytes(),
                                ));
                                break;
                            }
                        }
                        if upload_result.is_some() {
                            break;
                        }
                        if let Err(e) = async_file.flush().await {
                            eprintln!("Error flushing temp file: {:?}", e);
                            upload_result = Some((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Error flushing temp file".to_string().into_bytes(),
                            ));
                            break;
                        }
                        drop(async_file);
                        buffered_file = Some(tmp);
                        // Continue loop to find path field
                        continue;
                    }

                    // FAST PATH: path already set, stream directly
                    // if path ends on /, remove it
                    if path.ends_with("/") {
                        debug_log!("Removing trailing /, workaround");
                        path.pop();
                    }

                    let full_path = format!("{}/{}", path, file0_filename);

                    // validate path for traversal
                    match validate_path(&full_path) {
                        Ok(_) => (),
                        Err(e) => {
                            upload_result = Some((StatusCode::BAD_REQUEST, e.into_bytes()));
                            break;
                        }
                    }

                    // verify upload permissions
                    match verify_upload_permissions(&owner, &path) {
                        Ok(_) => (),
                        Err(e) => {
                            upload_result = Some((StatusCode::FORBIDDEN, e.to_string().into_bytes()));
                            break;
                        }
                    }

                    let hdr_content_type = headers.get("Content-Type-Upstream");
                    let semaphore = get_or_create_semaphore(&state.file_locks, &full_path).await;

                    // Try to acquire permit - wait for up to 30 seconds
                    let _permit = match tokio::time::timeout(
                        tokio::time::Duration::from_secs(30),
                        semaphore.acquire(),
                    )
                    .await
                    {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) => {
                            upload_result = Some((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Semaphore closed".to_string().into_bytes(),
                            ));
                            break;
                        }
                        Err(_) => {
                            upload_result = Some((
                                StatusCode::CONFLICT,
                                "Timeout waiting for upload".to_string().into_bytes(),
                            ));
                            break;
                        }
                    };

                    let content_type: String = match hdr_content_type {
                        Some(content_type) => content_type.to_str().unwrap().to_string(),
                        None => {
                            let heuristic_ctype = heuristic_filetype(file0_filename.clone());
                            debug_log!(
                                "Content-Type not found, using heuristics: {}",
                                heuristic_ctype
                            );
                            heuristic_ctype
                        }
                    };

                    // Stream the file upload directly
                    debug_log!("Starting streaming upload for {}", full_path);
                    let mut field_stream = FieldStream::new(field);
                    let driver_name = get_driver_type();
                    let driver = init_driver(&driver_name);

                    let (result, file_size) = driver.write_file_streaming(
                        full_path.clone(),
                        &mut field_stream,
                        content_type.to_string(),
                        Some(owner.clone()),
                    ).await;

                    if result.is_empty() {
                        upload_result = Some((StatusCode::CONFLICT, Vec::new()));
                        break;
                    }

                    let status = StatusCode::OK;
                    let client_ip = client_ip_from_headers(&headers, remote_addr);
                    let timestamp = std::time::SystemTime::now();
                    let human_time = chrono::DateTime::<chrono::Utc>::from(timestamp);
                    let request_target = original_uri.to_string();
                    println!(
                        "{} {} {} {} {} {} {} {}",
                        client_ip,
                        status.as_u16(),
                        file_size,
                        human_time,
                        Method::POST,
                        request_target,
                        full_path,
                        owner
                    );

                    upload_result = Some((status, Vec::new()));
                    break;
                }
                None => {
                    let error_msg = "No filename provided".to_string();
                    eprintln!("{}", error_msg);
                    upload_result = Some((StatusCode::BAD_REQUEST, error_msg.into_bytes()));
                    break;
                }
            }
        } else {
            let data = field.bytes().await;
            match data {
                Ok(data) => {
                    debug_log!("Unknown field {}: {} bytes", name, data.len());
                }
                Err(e) => {
                    eprintln!("Error reading field {}: {:?}", name, e);
                }
            }
        }
    }

    // Handle buffered file0 case (file0 arrived before path)
    if upload_result.is_none() {
        if let Some(tmp) = buffered_file {
            if path.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    b"Missing path field in upload".to_vec(),
                );
            }

            if path.ends_with("/") {
                debug_log!("Removing trailing /, workaround");
                path.pop();
            }

            let full_path = format!("{}/{}", path, file0_filename);

            match validate_path(&full_path) {
                Ok(_) => (),
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, e.into_bytes());
                }
            }

            match verify_upload_permissions(&owner, &path) {
                Ok(_) => (),
                Err(e) => {
                    return (StatusCode::FORBIDDEN, e.to_string().into_bytes());
                }
            }

            let hdr_content_type = headers.get("Content-Type-Upstream");
            let semaphore = get_or_create_semaphore(&state.file_locks, &full_path).await;

            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    return (
                        StatusCode::CONFLICT,
                        "Upload already in progress".to_string().into_bytes(),
                    );
                }
            };

            let content_type: String = match hdr_content_type {
                Some(content_type) => content_type.to_str().unwrap().to_string(),
                None => {
                    let heuristic_ctype = heuristic_filetype(file0_filename.clone());
                    debug_log!(
                        "Content-Type not found, using heuristics: {}",
                        heuristic_ctype
                    );
                    heuristic_ctype
                }
            };

            debug_log!("Starting buffered upload for {}", full_path);
            let mut async_file = match tokio::fs::File::open(tmp.path()).await {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to reopen temp file: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to reopen temp file".to_string().into_bytes(),
                    );
                }
            };

            let driver_name = get_driver_type();
            let driver = init_driver(&driver_name);

            let (result, file_size) = driver
                .write_file_streaming(
                    full_path.clone(),
                    &mut async_file,
                    content_type.to_string(),
                    Some(owner.clone()),
                )
                .await;

            // tmp (NamedTempFile) is dropped here, auto-deleting the temp file

            if result.is_empty() {
                return (StatusCode::CONFLICT, Vec::new());
            }

            let status = StatusCode::OK;
            let client_ip = client_ip_from_headers(&headers, remote_addr);
            let timestamp = std::time::SystemTime::now();
            let human_time = chrono::DateTime::<chrono::Utc>::from(timestamp);
            let request_target = original_uri.to_string();
            println!(
                "{} {} {} {} {} {} {} {} buggyclient",
                client_ip,
                status.as_u16(),
                file_size,
                human_time,
                Method::POST,
                request_target,
                full_path,
                owner
            );

            return (status, Vec::new());
        }
    }

    // Return the upload result if we processed the file
    if let Some(result) = upload_result {
        return result;
    }

    // If we get here, something went wrong (no file0 field found)
    debug_log!("No file0 field found in multipart upload");
    (StatusCode::BAD_REQUEST, b"No file0 field in upload".to_vec())
}

fn filename_from_fullpath(filepath: &str) -> String {
    let path = path::Path::new(filepath);
    let filename = path.file_name();
    match filename {
        Some(filename) => filename.to_str().unwrap().to_string(),
        None => filepath.to_string(),
    }
}

/*
    Retrieve file in the server from the cache/storage and return it to the client

    curl -X GET http://localhost:3000/v1/file/test.bin -H "Authorization: Bearer SuperSecretToken"

    This function will check if the Authorization header is present and if the token is correct
    If the token is correct, it will return the content of the file u8

*/
//     req: Request<Body>,

#[axum::debug_handler]
async fn ax_get_file(
    Path(filepath): Path<String>,
    rxheaders: HeaderMap,
    method: Method,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let timestamp = std::time::SystemTime::now();
    let human_time = chrono::DateTime::<chrono::Utc>::from(timestamp);
    let user_agent = rxheaders.get("User-Agent");
    let user_agent_str = match user_agent {
        Some(user_agent) => user_agent.to_str().unwrap(),
        None => "",
    };

    let semaphore = get_or_create_semaphore(&state.file_locks, &filepath).await;
    // Wait for permit with timeout
    let _permit =
        match tokio::time::timeout(tokio::time::Duration::from_secs(30), semaphore.acquire()).await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Semaphore closed").into_response();
            }
            Err(_) => {
                return (StatusCode::REQUEST_TIMEOUT, "Timeout waiting for upload").into_response();
            }
        };

    // IMPORTANT! Headers in cache must be stored in lowercase
    let received_file = driver_get_file(filepath.clone());
    if !received_file.valid {
        println!(
            "{:?} 404 0 {} {} {} {}",
            remote_addr, human_time, method, filepath, user_agent_str
        );
        return (StatusCode::NOT_FOUND, format!("Not Found: {}", filepath)).into_response();
    }
    let cached_file = received_file.cached_filename;
    let original_filename = received_file.original_filename;
    let upstream_headers = received_file.headers;
    //let file: tokio::fs::File;
    let metadata = tokio::fs::metadata(&cached_file).await.unwrap();
    let mut headers = HeaderMap::new();
    if let Some(content_type) = upstream_headers.get(CONTENT_TYPE) {
        headers.insert(header::CONTENT_TYPE, content_type.clone());
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );
    }
    let filename_only = filename_from_fullpath(&original_filename);
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename_only)
            .parse()
            .unwrap(),
    );

    headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    // add e-tag header from received_file.headers
    if let Some(etag) = upstream_headers.get(ETAG) {
        headers.insert(header::ETAG, etag.clone());
    }
    // add last-modified header
    if let Some(last_modified) = upstream_headers.get(LAST_MODIFIED) {
        headers.insert(header::LAST_MODIFIED, last_modified.clone());
    }

    // TODO: rxheaders.get is case sensitive or not?
    // Does request have If-None-Match header?
    if let Some(if_none_match) = rxheaders.get("If-None-Match") {
        // §13.1.2, last paragraph, RFC 9110
        if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
            return (StatusCode::PRECONDITION_FAILED, "Method Not Allowed").into_response();
        }
        if let Some(etag) = upstream_headers.get(ETAG) {
            if if_none_match == etag {
                println!(
                    "{:?} 304 0 {} {} {} {}",
                    remote_addr, human_time, method, filepath, user_agent_str
                );
                return (StatusCode::NOT_MODIFIED, headers, Body::empty()).into_response();
            }
        }
    // Does request have If-Modified-Since header?
    } else if let Some(if_modified_since) = rxheaders.get("If-Modified-Since") {
        if let Some(last_modified) = upstream_headers.get(LAST_MODIFIED) {
            // TODO: Validate properly last_modified
            if if_modified_since == last_modified {
                println!(
                    "{:?} 304 0 {} {} {} {}",
                    remote_addr, human_time, method, filepath, user_agent_str
                );
                return (StatusCode::NOT_MODIFIED, headers, Body::empty()).into_response();
            }
        }
    }

    /* Usually HEAD is used to check if the file exists and range is supported */
    if method == axum::http::Method::HEAD {
        if let Ok(val) = header::HeaderValue::from_str(&metadata.len().to_string()) {
            headers.insert(header::CONTENT_LENGTH, val);
        }
        println!(
            "{:?} 200 0 {} {} {} {}",
            remote_addr, human_time, method, filepath, user_agent_str
        );
        return (headers, Body::empty()).into_response();
    }

    match tokio::fs::File::open(&cached_file).await {
        Ok(mut file) => {
            let mut start = 0;
            let mut end = metadata.len();
            // is Content-Range present?
            if let Some(range) = rxheaders.get("Range") {
                match range.to_str().ok().and_then(parse_range) {
                    Some(parsed) => (start, end) = parsed,
                    None => {
                        return (StatusCode::RANGE_NOT_SATISFIABLE, "Malformed Range header").into_response();
                    }
                }
            }
            // if start is set to non-zero, we need to seek
            if start != 0 && (end == metadata.len() || end == 0) {
                file.seek(std::io::SeekFrom::Start(start)).await.unwrap();
                headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes {}-", start).parse().unwrap(),
                );
                if end == 0 || end >= metadata.len() {
                    end = metadata.len();
                }
                headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end - 1, metadata.len())
                        .parse()
                        .unwrap(),
                );
                headers.insert(
                    header::CONTENT_LENGTH,
                    format!("{}", end - start).parse().unwrap(),
                );
            } else {
                headers.insert(
                    header::CONTENT_LENGTH,
                    format!("{}", metadata.len()).parse().unwrap(),
                );
            }
            // If end... who cares about end :-D
            // Well, we need to implement it
            // TODO: implement "end" limit
            let stream = ReaderStream::new(file);
            let axbody = Body::from_stream(stream);

            //println!("Headers: {:?}", headers);
            if start != 0 {
                let body_size = end - start;
                println!(
                    "{:?} 206 {} {} {} {} {}",
                    remote_addr, body_size, human_time, method, filepath, user_agent_str
                );
                return (StatusCode::PARTIAL_CONTENT, headers, axbody).into_response();
            }
            println!(
                "{:?} 200 {} {} {} {} {}",
                remote_addr,
                metadata.len(),
                human_time,
                method,
                filepath,
                user_agent_str
            );
            return (StatusCode::OK, headers, axbody).into_response();
        }
        Err(_) => {
            eprintln!("Error opening file in ax_get_file");
            println!(
                "{:?} 404 0 {} {} {} {}",
                remote_addr, human_time, method, filepath, user_agent_str
            );
            (StatusCode::NOT_FOUND, headers, Body::empty()).into_response()
        }
    }
}

fn driver_get_file(filepath: String) -> ReceivedFile {
    let driver_name = get_driver_type();
    let driver = init_driver(&driver_name);
    driver.get_file(filepath)
}

fn write_file_driver(
    filename: String,
    data: Vec<u8>,
    cont_type: String,
    owner_email: Option<String>,
) -> String {
    let driver_name = get_driver_type();
    let driver = init_driver(&driver_name);
    driver.write_file(filename, data, cont_type, owner_email);
    "".to_string()
}

/// Parse range header
/// We support limited range only for now
fn parse_range(range: &str) -> Option<(u64, u64)> {
    let (_, range_spec) = range.split_once('=')?;
    let (start_str, end_str) = range_spec.split_once('-')?;
    let start = start_str.parse::<u64>().ok()?;
    let end = end_str.parse::<u64>().unwrap_or(0);
    Some((start, end))
}

/// Verify the Authorization header
/// Return error message + owner if the token is correct
fn verify_auth_hdr(headers: &HeaderMap) -> Result<String, Option<String>> {
    let auth = match headers.get("Authorization") {
        Some(auth) => auth,
        None => return Err(None),
    };
    let auth_str = match auth.to_str() {
        Ok(s) => s,
        Err(_) => return Err(None),
    };
    let token_parts: Vec<&str> = auth_str.split_whitespace().collect();
    if token_parts.is_empty() {
        return Err(None);
    }
    if token_parts.len() != 2 {
        let verif_result = storjwt::verify_jwt_token(token_parts[0]);
        let bmap = match verif_result {
            Ok(bmap) => bmap.clone(),
            Err(_) => {
                eprintln!("Error verifying token");
                return Err(None);
            }
        };
        if let Some(email) = bmap.get("email") {
            return Ok(email.to_string());
        } else {
            return Err(None);
        }
    }
    let verif_result = storjwt::verify_jwt_token(token_parts[1]);
    let bmap = match verif_result {
        Ok(bmap) => bmap.clone(),
        Err(_) => {
            eprintln!("Error verifying bearer token");
            return Err(None);
        }
    };
    if let Some(email) = bmap.get("email") {
        Ok(email.to_string())
    } else {
        Err(None)
    }
}

async fn ax_list_files() -> (StatusCode, String) {
    let driver_name = get_driver_type();
    let driver = init_driver(&driver_name);
    let files = driver.list_files("/".to_string());
    // generate nice list of files, with one file per line
    let files_str = files.join("\n");
    (StatusCode::OK, files_str)
}
