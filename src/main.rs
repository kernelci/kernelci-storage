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
mod storcaching;
mod storjwt;

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, State},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use headers::HeaderMap;
use std::path;
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::AsyncSeekExt;
use tokio_util::io::ReaderStream;
use toml::Table;
use tower::ServiceBuilder;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{RwLock, Semaphore};
use sysinfo::Disks;

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


async fn get_or_create_semaphore(
    locks: &FileSemaphores,
    filename: &str,
) -> Arc<Semaphore> {
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

trait Driver {
    fn write_file(&self, filename: String, data: Vec<u8>, cont_type: String) -> String;
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
        //"google" => Box::new(google::GoogleDriver::new()),
        _ => {
            eprintln!("Unknown driver type");
            std::process::exit(1);
        }
    };
    driver
}

pub fn get_config_content() -> String {
    let args = Args::parse();
    let mut cfg_file = PathBuf::from(&args.config_file);
    if let Ok(cfg_file_env) = std::env::var("KCI_STORAGE_CONFIG") {
        cfg_file = PathBuf::from(&cfg_file_env);
    }
    
    std::fs::read_to_string(&cfg_file).unwrap()
}

/// Initial variables configuration and checks
async fn initial_setup() -> Option<RustlsConfig> {
    let cache_dir = "cache";
    let download_dir = "download";
    let args = Args::parse();

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

    let _handle = tokio::spawn(storcaching::cache_loop(cache_dir));

    if !std::path::Path::new(download_dir).exists() {
        std::fs::create_dir(download_dir).unwrap();
    }

    let cfg_file: PathBuf;
    // is ENV KCI_STORAGE_CONFIG set?
    if let Ok(cfg_file_env) = std::env::var("KCI_STORAGE_CONFIG") {
        cfg_file = PathBuf::from(&cfg_file_env);
        println!("Using config file from ENV: {}", cfg_file.display());
    } else {
        cfg_file = PathBuf::from(&args.config_file);
        println!("Using config file from args: {}", cfg_file.display());
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
            println!("TLS config loaded, HTTPS mode enabled");
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
        
        metrics.push_str(&format!("storage_free_space {{hostname=\"{}\", diskname=\"{}\", mount_point=\"{}\"}} {}\n", hostname, tag_diskname, mount_point, tag_available_space));
        metrics.push_str(&format!("storage_total_space {{hostname=\"{}\", diskname=\"{}\", mount_point=\"{}\"}} {}\n", hostname, tag_diskname, mount_point, tag_total_space));
    }
    (StatusCode::OK, metrics)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let tlscfg = initial_setup().await;
    let port = 3000;
    let state = AppState {
        file_locks: Arc::new(RwLock::new(HashMap::new())),
    };
    println!("Starting server, tls: {:?}", tlscfg);

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
            println!("Authorized: {}", email);
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

fn verify_upload_permissions(owner: &str, path: &str) -> Result<(), String> {
    let cfg_content = get_config_content();
    let cfg: Table = toml::from_str(&cfg_content).unwrap();
    let users_r = cfg.get("users");
    let users = match users_r {
        Some(users) => users,
        None => {
            println!("No users section in config.toml, ignoring upload path restriction");
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
async fn ax_post_file(headers: HeaderMap, State(state): State<AppState>, mut multipart: Multipart) -> (StatusCode, Vec<u8>) {
    // call check_auth
    let message = verify_auth_hdr(&headers);
    let owner = match message {
        Ok(owner) => owner,
        Err(_) => return (StatusCode::UNAUTHORIZED, Vec::new()),
    };
    println!("Authorized");

    /* 100-continue Expect is broken, quite hard to fix in axum */
    /*
    if let Some(expect) = headers.get("Expect") {
        println!("Expect: {:?}", expect);
        if expect == "100-continue" {
            println!("Expect 100-continue");
            return (StatusCode::CONTINUE, Vec::new());
        }
    }
    */

    println!("Uploading file");
    let mut path: String = "".to_string();
    let mut file0: Vec<u8> = Vec::new();
    let mut file0_filename: String = "".to_string();
    

    // verify upload permissions, some users have upload permissions only for certain prefix(path)
    // check config.toml for upload_prefixes
    match verify_upload_permissions(&owner, &path) {
        Ok(_) => (),
        Err(e) => return (StatusCode::FORBIDDEN, e.to_string().into_bytes()),
    }


    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        //let filename = field.file_name();
        let filename = field.file_name().map(|f| f.to_string()); // Map filename to avoid borrowing later, how this black magic works?!?!?!
        let data = field.bytes().await;

        match data {
            Ok(data) => {
                println!("Length of `{}` is {} bytes", name, data.len());
                if name == "path" {
                    path = String::from_utf8(data.to_vec()).unwrap();
                    println!("Path: {}", path);
                } else if name == "file0" {
                    file0 = data.to_vec();
                    match filename {
                        Some(filename) => file0_filename = filename.to_string(),
                        None => todo!(),
                    }
                } else {
                    println!("Unknown field: {} len: {}", name, data.len());
                }
            }
            Err(e) => {
                eprintln!(
                    "Error reading file: {:?} for name {}. Axum size upload limit?",
                    e, name
                );
                return (StatusCode::BAD_REQUEST, Vec::new());
            }
        }
    }
    println!(
        "File: {} bytes filename: {} path: {}",
        file0.len(),
        file0_filename,
        path
    );
    // if path ends on /, remove it
    if path.ends_with("/") {
        // TBD: Fix it!
        println!("Removing trailing /, workaround");
        path.pop();
    }
    
    let full_path = format!("{}/{}", path, file0_filename);
    let hdr_content_type = headers.get("Content-Type-Upstream");
    let semaphore = get_or_create_semaphore(&state.file_locks, &full_path).await;
    
    // Try to acquire permit - fails immediately if upload in progress
    let permit = match semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return (StatusCode::CONFLICT, "Upload already in progress".to_string().into_bytes());
        }
    };

    let content_type: String = match hdr_content_type {
        Some(content_type) => {
            println!("Content-Type: {:?}", content_type);
            content_type.to_str().unwrap().to_string()
        }
        None => {
            let heuristic_ctype = heuristic_filetype(file0_filename);
            println!(
                "Content-Type not found, using heuristics: {}",
                heuristic_ctype
            );
            heuristic_ctype
        }
    };

    // TBD
    let message = write_file_driver(full_path, file0, content_type.to_string());
    if !message.is_empty() {
        return (StatusCode::CONFLICT, Vec::new());
    }
    // write metadata file into cache directory
    //let metadata_filename = format!("{}/{}.metadata", path, file0_filename);
    //write_cache_metadata(metadata_filename, file0.len());
    (StatusCode::OK, Vec::new())
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
    let _permit = match tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        semaphore.acquire(),
    ).await {
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
        println!("Stored content-Type: {:?}", content_type);
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
        //println!("HEAD request, returning headers only");
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
                println!("Range: {:?}", range);
                (start, end) = parse_range(range.to_str().unwrap());
            }
            // if start is set to non-zero, we need to seek
            if start != 0 && (end == metadata.len() || end == 0) {
                println!("Seeking to {}", start);
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
            println!("Error opening file in ax_get_file");
            println!(
                "{:?} 404 0 {} {} {} {}",
                remote_addr, human_time, method, filepath, user_agent_str
            );
            (StatusCode::NOT_FOUND, headers, Body::empty()).into_response()
        }
    }
}

fn driver_get_file(filepath: String) -> ReceivedFile {
    let driver_name = "azure";
    let driver = init_driver(driver_name);
    driver.get_file(filepath)
}

fn write_file_driver(filename: String, data: Vec<u8>, cont_type: String) -> String {
    let driver_name = "azure";
    let driver = init_driver(driver_name);
    driver.write_file(filename, data, cont_type);
    "".to_string()
}

/// Parse range header
/// We support limited range only for now
fn parse_range(range: &str) -> (u64, u64) {
    let parts: Vec<&str> = range.split("=").collect();
    let range_parts: Vec<&str> = parts[1].split("-").collect();
    let start = range_parts[0].parse::<u64>().unwrap();
    if range_parts.len() == 1 {
        return (start, 0);
    }
    let end = range_parts[1].parse::<u64>();
    match end {
        Ok(end) => (start, end),
        Err(_) => (start, 0),
    }
}

/// Verify the Authorization header
/// Return error message + owner if the token is correct
fn verify_auth_hdr(headers: &HeaderMap) -> Result<String, Option<String>> {
    let auth = headers.get("Authorization");
    if auth == None { return Err(None) }
    let token = auth.unwrap().to_str().unwrap().split_whitespace();
    let token_parts: Vec<&str> = token.collect();
    if token_parts.len() != 2 {
        let verif_result = storjwt::verify_jwt_token(token_parts[0]);
        let bmap = match verif_result {
            Ok(bmap) => bmap.clone(),
            Err(_) => {
                println!("Error verifying token");
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
            println!("Error verifying bearer token");
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
    let driver_name = "azure";
    let driver = init_driver(driver_name);
    let files = driver.list_files("/".to_string());
    // generate nice list of files, with one file per line
    let files_str = files.join("\n");
    (StatusCode::OK, files_str)
}
