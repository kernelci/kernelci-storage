# kernelci-storage ChangeLog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-10-23

### Added
- Streaming multipart upload support for large files (200MB+)
- New `write_file_streaming()` async method in Driver trait
- `FieldStream` wrapper to convert multipart fields to AsyncRead
- Streaming implementations for both Azure and Local storage backends
- `async-trait` dependency (0.1) for trait async methods
- `bytes` dependency (1.9) for efficient byte buffer handling

### Changed
- Refactored `ax_post_file` handler to stream uploads directly without loading entire file into memory
- Azure backend now streams uploads in 10MB chunks directly to blob storage
- Local backend now streams uploads in 10MB chunks directly to filesystem
- Upload handler processes multipart fields sequentially and starts streaming immediately

### Performance Improvements
- Reduced memory usage: Only 10MB buffer in memory at any time instead of entire file
- Improved upload performance for large files by eliminating full memory buffering
- Removed temporary file creation during Azure uploads (streaming directly from multipart)
- Better scalability: Can handle files larger than available RAM

### Technical Details
- No breaking changes to existing API - fully backward compatible
- Existing upload clients continue to work without modifications
- All existing functionality preserved (permissions, content-type, owner tags, file locking)
- Proper lifetime management for multipart field streaming
- Uses async/await with tokio AsyncRead trait

## [0.1.0] - 2025-01-06

### Added
- Initial release of KernelCI Storage Server
- JWT token-based authentication with HMAC-SHA256
- File upload/download with local caching
- Azure Blob Storage backend support with chunked uploads (10MB blocks)
- Local filesystem backend support
- Range request support for partial content downloads
- Prometheus metrics endpoint (`/metrics`)
- File locking mechanism to prevent concurrent uploads to same path
- Automatic cache cleanup when disk space < 12%
- LRU-style cache deletion (removes files older than 60 minutes)
- User-specific upload path restrictions via configuration
- SSL/TLS support with certificate configuration
- Docker support with Dockerfile

### Features
- RESTful API with endpoints:
  - `GET /` - Server status
  - `POST /upload` or `POST /v1/file` - File upload (requires JWT)
  - `GET /*filepath` - File download (public)
  - `GET /v1/checkauth` - Validate JWT token
  - `GET /v1/list` - List all files (public)
  - `GET /metrics` - Prometheus metrics
- Header preservation for HTTP caching (ETag, Last-Modified)
- Content-type detection with heuristics
- Configurable via TOML configuration file
- Environment variable override for config path (`KCI_STORAGE_CONFIG`)
- Verbose logging support via `--verbose` flag
- Command-line utilities:
  - `--generate-jwt-secret` - Generate JWT secret
  - `--generate-jwt-token` - Generate JWT token for user
- SHA-512 based cache filenames to avoid path conflicts
- Client IP detection with X-Forwarded-For support
- Disk space monitoring with hysteresis
