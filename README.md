# KernelCI Storage Server

This is a simple storage server that supports file upload and download, with token based authentication.
It supports multiple backends: Azure Blob Storage and local filesystem, to provide user transparent storage.
It caches the files in a local directory and serves them from there.
Range requests are supported, but only for start offset, end limit is not implemented yet.
Files are protected by upload locking to prevent concurrent uploads to the same path.

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

### Metrics

The `/metrics` endpoint provides Prometheus-compatible metrics including:
- `storage_free_space` - Available disk space
- `storage_total_space` - Total disk space

Both metrics include hostname, diskname, and mount_point labels.

## API Documentation

See [docs](docs/) for detailed API documentation.