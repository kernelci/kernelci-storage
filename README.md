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

### Banning User-Agents

To keep out web crawlers, scrapers, and AI agents, requests are rejected by
`User-Agent` header. Any request whose `User-Agent` contains one of the banned
substrings (case-insensitive) is answered with `403 Forbidden` before it
reaches any handler, and the rejection is logged.

A curated **built-in list is always applied**. It blocks the common "lesser"
search-engine crawlers (Yandex, Baidu, DuckDuckGo, Yahoo, Sogou, Seznam, Naver,
Qwant, Petal, ...), common AI scrapers (GPTBot, CCBot, ClaudeBot,
PerplexityBot, Bytespider, ...), and SEO/marketing crawlers (AhrefsBot,
SemrushBot, MJ12bot, DotBot, BLEXBot, ...), while **always allowing Google (`Googlebot`)
and Microsoft (`bingbot`/`msnbot`)** so artifacts stay indexable by the two
major engines.

You can extend the built-in list, or turn it off entirely, via the optional
`[useragent]` section:

```toml
[useragent]
# Extra case-insensitive substrings to ban, on top of the built-in list.
ban = ["SomeOtherBot", "AnotherScraper"]
# Set to false to disable the built-in list and ban only the substrings above.
defaults = true
```

The effective list is read once at startup and cached, so restart the server to
apply changes.

In addition, the server serves a prohibitive `/robots.txt` (`User-agent: *` /
`Disallow: /`) that asks every crawler to stay out. (The User-Agent ban is the
hard enforcement; robots.txt is the polite request layer for crawlers that
honour it.)

### Blocking IP Subnets

Use the optional top-level `block_subnets` setting to reject client addresses
from one or more IPv4 or IPv6 networks. List multiple CIDRs in a TOML array:

```toml
block_subnets = [
    "192.0.2.0/24",
    "198.51.100.0/24",
    "2001:db8::/32",
]
```

Use a `/32` IPv4 prefix or `/128` IPv6 prefix to block one address. Matching
requests receive `403 Forbidden` before reaching a handler and are logged as
`event=subnet_ban`. Invalid CIDRs prevent the server from starting, and a
restart is required after changing the list.

When running behind a reverse proxy, ensure it overwrites the forwarded-client
headers and prevent direct access to the storage origin. The server uses the
same resolved client IP for access logging and subnet matching.

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
- `POST /v1/archive` - Tar archive upload with server-side extraction (requires JWT)
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

### Uploading Many Files as an Archive

For large batches of small files, such as hundreds of DTBs, upload a tar archive to `/v1/archive`. The server extracts regular files from `.tar`, `.tar.gz`, `.tgz`, `.tar.zst`, `.tzst`, `.tar.xz`, or `.txz` archives and writes each file as an individual object through the configured storage backend.

```bash
tar -cJf dtbs.tar.xz -C /path/to/build/dtbs .

curl -X POST http://localhost:3000/v1/archive \
    -H "Authorization: Bearer <JWT_TOKEN>" \
    -F "path=artifacts/build-123/dtbs" \
    -F "archive=@dtbs.tar.xz"
```

Archive entries are stored under the requested prefix. The server rejects path traversal, absolute paths, links, devices, and other non-regular files. Upload concurrency defaults to 4 files and can be adjusted with `KCI_STORAGE_ARCHIVE_PARALLELISM`.

### Metrics

The `/metrics` endpoint provides Prometheus-compatible metrics including:
- `storage_free_space` - Available disk space
- `storage_total_space` - Total disk space

Both metrics include hostname, diskname, and mount_point labels.

## API Documentation

See [docs](docs/) for detailed API documentation.
