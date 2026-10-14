# KernelCI Storage Server

This is a simple storage server that supports file upload and download, with token based authentication.
It supports multiple backends: Azure Blob Storage and local filesystem, to provide user transparent storage.
It caches the files in a local directory and serves them from there.
Single byte ranges support start offsets and optional end limits.
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

Forwarded client addresses are used only when the connection comes from a
configured proxy. Add its CIDRs at the top level of the configuration:

```toml
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/24"]
trusted_proxy_header = "x-forwarded-for"  # or "forwarded"
```

The default is an empty list, which uses the connection address. The server
walks the forwarded chain from right to left and uses the first address outside
these proxy ranges for logging, subnet matching, and challenge cookies. Configure
only your proxy addresses and select the header your proxy appends or overwrites.
The default header is `x-forwarded-for`; the other header family is ignored. Invalid proxy CIDRs prevent startup.

### Browser Download Challenge

The optional browser challenge gives configured User-Agent patterns a short
preparation page before downloading. JavaScript requests a server-signed,
short-lived cookie bound to the client's IPv4 or IPv6 network and then reloads
the artifact. The feature is disabled when `[download_challenge]` is absent or
when `user_agents` is empty.

```toml
[download_challenge]
user_agents = ["android"]  # case-insensitive substrings
secret = "replace-with-an-independent-random-secret-of-at-least-32-characters"
cookie_ttl_seconds = 600   # 30..86400; defaults to 600
ipv4_prefix_length = 24    # defaults to 24
ipv6_prefix_length = 64    # defaults to 64
fallback_bytes_per_second = 262144  # optional; 0 or absent disables fallback
secure_cookie = true       # keep true in production HTTPS deployments
```

The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` by default. The
preparation page is marked `no-store` and includes a manual fallback only when
`fallback_bytes_per_second` is configured. Fallback responses carry
`X-Accel-Limit-Rate`, which Nginx uses to limit response bandwidth. The server
logs challenged requests as `event=download_challenge`.

This is a lightweight defense against clients that do not execute the browser
flow, not proof that a client is human. Keep backend concurrency and rate
limits in place. Configure `trusted_proxies` when a proxy supplies client addresses.

## Creating user tokens

The server uses JWT token based authentication. The token is passed in the `Authorization` header as a Bearer token.
JWT secret is configured in the `config.toml` file.

```bash
# Generate JWT secret
./kernelci-storage --generate-jwt-secret

# Generate JWT token for a user
./kernelci-storage --generate-jwt-token user@email.com
```
The first command generates a JWT secret for your configuration; the second
generates a token for the specified user with a 24-hour lifetime. Supplied
expiration claims are checked without a grace period. Existing tokens without
an expiration claim remain accepted for compatibility.

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
- `STORAGE_MONITOR_SECS` - Interval of the runtime stall monitor (default 15, `0` disables it)

### Runtime Stall Monitor

A dedicated OS thread (not a tokio task, so it keeps running when the async
runtime is wedged) checks the server every `STORAGE_MONITOR_SECS` seconds and
prints to stderr only when something is unusual:

- `event=runtime_stall` / `event=runtime_recovered` - a trivial task spawned onto the
  runtime did not run within 5 seconds; while stalled, a thread dump
  (`event=monitor_dump` + one `event=monitor_thread` line per non-idle thread with
  its state, current syscall, wait channel and, where the kernel allows it, kernel
  stack) is printed at most once a minute.
- `event=monitor_warn` - a worker thread neither parked nor went idle for a whole
  interval (blocked in a syscall or hogging the CPU), several threads are in
  uninterruptible sleep, the scheduling probe was slow, or the task or
  blocking-thread counts are far outside normal.

Runtime threads are named `rt-worker-NN` (scheduler workers) and `rt-blocking-NN`
(blocking pool) so dumps, `top -H` and `/proc/<pid>/task` tell them apart. With
`STORAGE_DEBUG` set, a `monitor_tick` summary line is printed every interval.

## API

### Endpoints

- `GET /` - Server status
- `POST /v1/file` or `POST /upload` - File upload (requires JWT)
- `POST /v1/archive` - Tar archive upload with server-side extraction (requires JWT)
- `GET /*filepath` - File download (public, supports range requests)
- `GET /v1/checkauth` - Validate JWT token
- `GET /v1/list` - List all files (public)
- `GET /metrics` - Prometheus metrics endpoint

The server supports uploads up to 4GB. Uploads in either multipart field order
and downloads wait up to 30 seconds for an existing operation on the same path.
Buffered uploads and extracted archives use the workspace's `download/`
directory, so reserve space there for both the archive and its extracted files.
Upload prefixes match whole path components; leading and trailing slashes are
optional. Invalid `[[users]]` configurations are rejected at startup.

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

Archive entries are stored under the requested prefix. The server rejects path traversal, absolute paths, links, devices, and other non-regular files. Backend writes from all concurrent archive requests share one process-wide asynchronous limit of 16 by default. Adjust it with `KCI_STORAGE_ARCHIVE_PARALLELISM`.

### Metrics

The `/metrics` endpoint provides Prometheus-compatible metrics including:
- `storage_free_space` - Available disk space
- `storage_total_space` - Total disk space

Both metrics include hostname, diskname, and mount_point labels.

## API Documentation

See [docs](docs/) for detailed API documentation.
