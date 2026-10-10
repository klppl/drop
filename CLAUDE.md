# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`drop` is a self-hosted file-sharing service: a single Go binary with no external dependencies, fronted by nginx in Docker. Users upload files via `curl` or browser and get back a short URL.

## Commands

```bash
# Build the binary locally
go build -o drop .

# Run locally (DATA_DIR defaults to /data: files in files/, metadata in meta/, log uploads.log)
DATA_DIR=./data go run .

# Run in purge mode (age-expires files on demand)
go run . purge

# Health check (what the Docker HEALTHCHECK runs)
go run . health

# Tests
go vet ./... && go test -race ./...

# Docker (production)
cp .env.example .env
# Edit .env — set UPLOAD_TOKEN and ADMIN_PASSWORD
docker compose up -d --build

# Manually trigger a purge inside the running container
docker compose exec drop /app/drop purge
```

Tests live in `main_test.go` and drive the real handler from `newMux()` against a temp `DATA_DIR`. CI runs them (`.github/workflows/test.yml`).

## Architecture

All code lives in a single file: `main.go` (tests in `main_test.go`). The binary runs as an HTTP server (default port 8080) behind nginx.

**Request flow:**
- `POST /` (multipart) → `handleUpload` — authenticates, validates extension + MIME, re-encodes raster images (strips EXIF), creates `/data/files/<id>.<ext>` with `O_EXCL`, writes `/data/meta/<name>.json`, logs to `/data/uploads.log`. Optional fields: `id_length`, `expires`, `burn`. Response headers: `X-Delete-Token`, `X-Expires`
- `POST /` (urlencoded) → `action=login` / `action=logout` for upload-token browser sessions (body capped at 64 KiB; multipart bodies must never be parsed here, before auth)
- `GET|HEAD /f/<id>.<ext>` → `handleFiles` — serves files; only `jpg/jpeg/png/gif` are served inline, all others force download. Expired files 404 and are removed; burn files are claimed by atomic rename into `/data/burn/` on the first non-admin GET
- `DELETE /f/<id>.<ext>` → `handleDelete` — requires `X-Delete-Token` matching the stored sha256 hash
- `GET /healthz` → `handleHealth`
- `GET|POST /admin` → `handleAdmin` — session-based admin panel (list/delete files, bulk purge, view log)
- `GET /?sharex` / `GET /?hupl` → `serveShareX` / `serveHupl` — download pre-filled uploader config files (token baked in only for logged-in sessions; upload sessions always get their own token)

**Background goroutines:**
- `startCleaner` (hourly): expiry purge via `purgeDecay` (retention formula or the uploader's earlier `expires`), `sweepMeta` (orphan metadata, stale burn files), disk-pressure eviction (`evictOldest`) if disk > 90%
- Session/login-fail janitor (every 30 min)

**Storage:**
- Files: `/data/files/<randomID>.<ext>` (4–24 char alphanum IDs); always delete via `removeStored` so metadata goes too
- Metadata: `/data/meta/<name>.json` (`fileMeta`: delete-token hash, expires, burn); missing = zero value
- App tokens: `/data/tokens.json` (plaintext so per-token configs can be re-downloaded; written 0600 via `writeFileAtomic`)
- Log: `/data/uploads.log` (TSV: timestamp, IP, size, original name, stored name)
- Sessions: in-memory `sync.Map` (not persistent across restarts); upload sessions keep the token they logged in with and die when it is revoked

**File retention formula:**
```
days = MIN_FILE_AGE + (MAX_FILE_AGE − MIN_FILE_AGE) × (1 − size ÷ MAX_FILESIZE)²
```

**Security properties to preserve:**
- JPEG/PNG/GIF are decoded to pixels and re-encoded to strip EXIF and active content
- Non-inline types (`pdf`, `webp`, `avif`, `heic`, `txt`, `md`, etc.) are forced to download — never rendered inline
- SVG, HTML, XML are intentionally not in the allowlist (XSS risk)
- Upload token auth checked via `Authorization: Bearer` header, `X-Upload-Token` header, or form field
- Admin password compared with `subtle.ConstantTimeCompare`; login rate-limited per IP (10 attempts/hour)
- `X-Real-IP` (set by nginx from `$remote_addr`) is trusted over `X-Forwarded-For` (client-controlled)
- Decompression-bomb guard: image dimensions checked via `image.DecodeConfig` before full decode (50 MP cap); GIF frames summed by `gifTotalPixels` (200 MP cap)
- Images that fail to decode are rejected (never stored raw)
- ShareX/Hupl configs only embed a token for logged-in sessions; anonymous downloads (auth off) get none
- Upload sessions keep their token in memory only, and die when it is revoked
- Rate limits key on `clientIP`, which strips the port from `RemoteAddr`

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `UPLOAD_TOKEN` | *(empty)* | Required for auth; empty = open uploads |
| `REQUIRE_AUTH` | `true` if token set | Override auth behaviour |
| `UPLOAD_RATE_LIMIT` | `60` | Anonymous uploads/IP/hour (auth off only); `0` = unlimited |
| `MAX_FILESIZE` | `256` | MiB; also update `NGINX_MAX_BODY_MIB` to `MAX_FILESIZE + 2` |
| `NGINX_MAX_BODY_MIB` | `258` | nginx `client_max_body_size`; must stay in sync |
| `MAX_FILE_AGE` | `30` | Days (smallest files) |
| `MIN_FILE_AGE` | `3` | Days (largest files) |
| `ADMIN_PASSWORD` | `changeme` | `/admin` panel password |
| `ADMIN_EMAIL` | `admin@example.com` | Shown on index page |
| `TZ` | `UTC` | Log timestamps |
| `PORT` | `8080` | Listening port |
| `DATA_DIR` | `/data` | Storage root |

## nginx / Docker notes

- nginx uses `envsubst` templating — the active config template is `nginx/templates/default.conf.template`; `nginx/default.conf` is a static fallback
- The `drop` container runs as non-root user `drop` (UID 65534), with `read_only: true` filesystem and a `/tmp` tmpfs (Go multipart temp files)
- The Docker healthcheck (`--interval=30s`) runs `/app/drop health`, which GETs `/healthz`
