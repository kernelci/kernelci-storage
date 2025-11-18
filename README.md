# KernelCI Storage Server

This is a simple storage server that supports file upload and download, with token based authentication.
It supports multiple backends: Azure Blob Storage and local filesystem, to provide user transparent storage.
It caches the files in a local directory and serves them from there.
Range requests are supported, but only for start offset, end limit is not implemented yet.
Files are protected by upload locking to prevent concurrent uploads to the same path.
To limit disk usage, a background housekeeping loop samples disk space every five minutes, keeps the cache below 1,000,000 items, and deletes the oldest cached files in configurable batches (default 100,000 files) whenever the file-count or disk-space thresholds are exceeded. A housekeeping summary is logged every five minutes showing the current free space, cache size, and any clean-up actions taken.

## Configuration

The server is configured using toml configuration file, the default configuration file is `config.toml`.

### Azure Backend Configuration

```toml
driver="azure"  # Optional, defaults to "azure"
jwt_secret="JWT_SECRET"
[azure]
account=""
key=""
container=""
sastoken=""

# User upload permissions (optional)
[[users]]
name = "user@email.com"
prefixes = ["/allowed/path"]
```

### Local Filesystem Backend Configuration

```toml
driver="local"
jwt_secret="JWT_SECRET"
[local]
storage_path="./storage"  # Optional, defaults to "./storage"

# User upload permissions (optional)
[[users]]
name = "user@email.com"
prefixes = ["/allowed/path"]
```

### Cache Housekeeping

Cache housekeeping enforces a hard limit of 1,000,000 cached artifacts (`*.content` files) and frees disk space whenever free capacity drops below 12% (stopping once it rises above 13%). Files are always deleted in least-recently-updated order. The size of each deletion batch is configurable via the optional `[cache]` section:

```toml
[cache]
# Number of cached files deleted per housekeeping iteration when limits are exceeded
cleanup_chunk_size = 100000  # Defaults to 100000
```

Larger chunk sizes reclaim space faster when the cache is far above the limit, while smaller chunks reduce the amount of data removed per iteration.

## Creating user tokens

The server uses JWT token based authentication. The token is passed in the `Authorization` header as a Bearer token.
JWT secret is configured in the `config.toml` file.

```bash
# Generate JWT secret
./kernelci-storage --generate-jwt-secret

# Generate JWT token for a user
./kernelci-storage --generate-jwt-token user@email.com
```
The first command generates a JWT secret for your configuration, the second generates a token for the specified user.

### Testing Token Validity

You can verify if a token is valid using the `/v1/checkauth` endpoint:

```bash
curl -X GET https://localhost:3000/v1/checkauth \
    -H "Authorization: Bearer <JWT_TOKEN>"
```

**Responses:**
- `200 OK` with body `Authorized: user@email.com` - Token is valid
- `401 Unauthorized` with body `Unauthorized` - Token is invalid or missing

## Environment Variables

- `KCI_STORAGE_CONFIG` - Override config file path (defaults to config.toml)
- `STORAGE_DEBUG` - Enable debug logging

## API

### Endpoints

- `GET /` - Server status
- `POST /v1/file` or `POST /upload` - File upload (requires JWT)
- `GET /*filepath` - File download (public, supports range requests)
- `GET /v1/checkauth` - Validate JWT token
- `GET /v1/list` - List all files (public)
- `GET /metrics` - Prometheus metrics endpoint

The server supports large file uploads up to 4GB and includes upload conflict protection to prevent concurrent uploads to the same file path. Downloads have a 30-second timeout for acquiring file locks.

### Uploading Files with curl

Use `curl`'s multipart form support to send the file contents (`file0`) and target path. The upload endpoint accepts both `/upload` and `/v1/file`.

```bash
curl -X POST http://localhost:3000/v1/file \
    -H "Authorization: Bearer <JWT_TOKEN>" \
    -F "path=artifacts/build-123" \
    -F "file0=@/absolute/path/to/build-output.tar.xz"
```

The resulting object is stored under `artifacts/build-123/<local filename>`. Swap in `/upload` if you prefer the shorter alias or use the public host name instead of `localhost` when interacting with a remote server.

### Metrics

The `/metrics` endpoint provides Prometheus-compatible metrics including:
- `storage_free_space` - Available disk space
- `storage_total_space` - Total disk space

Both metrics include hostname, diskname, and mount_point labels.

## API Documentation

See [docs](docs/) for detailed API documentation.
