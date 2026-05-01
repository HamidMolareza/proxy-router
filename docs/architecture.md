# Architecture

## Overview

`proxy-router` has two main runtime parts:

- A Python backend that accepts proxy traffic and exposes dashboard APIs
- A React frontend that renders the dashboard and talks to the backend through `/api/*`
- A WebSocket live-update channel at `/api/live` for pushed dashboard snapshots

In Docker, the backend and dashboard use separate Dockerfiles.

## Runtime Components

### Backend

Entry point:

- [`proxy-router`](../proxy-router)

Python package:

- [`proxy_router/`](../proxy_router)

Important backend modules:

- `cli.py`: argument parsing, startup, shutdown, listener wiring
- `proxy_server.py`: HTTP, CONNECT, mixed-port, and SOCKS5 handlers
- `certificates.py`: HTTPS interception CA and per-host certificate generation
- `dashboard_api.py`: dashboard API server and request handlers
- `runtime.py`: in-process runtime state, log writers, dashboard state, persistence rehydration
- `config.py`: router config management, rule normalization, network profile matching
- `traffic.py`: quota manager and auto-proxy failure manager
- `records.py`: history cache and failure snapshot support
- `util.py`: shared parsing, formatting, JSONL loading, history aggregation helpers
- `output.py`: console and debug logging helpers
- `constants.py`: shared constants and defaults

### Frontend

Frontend source:

- [`frontend/`](../frontend)

Purpose:

- Render the dashboard UI
- Poll backend APIs
- Edit router config
- Display history, HTTPS traffic analysis, routing, quotas, and failure review

## Request Flow

### Proxy traffic

1. A client connects to the mixed or SOCKS5 listener.
2. The backend validates the source network and resolves an anonymous IP identity or an authenticated `user:<username>` identity.
3. The backend evaluates quota state for that identity.
4. Routing rules are resolved from the active config and profile context.
5. HTTP CONNECT requests are either tunneled unchanged or, when HTTPS interception is enabled and matched, terminated with a generated host certificate.
6. The request is sent direct, proxied upstream, or blocked.
7. Usage, failure, and intercepted HTTPS analyzer events are written to persisted log files.
8. Runtime dashboard state is updated in memory.

### Dashboard traffic

1. A browser opens the dashboard frontend.
2. The frontend opens `/api/live` for pushed dashboard snapshots and change notifications.
3. The frontend still uses `/api/*` for filtered history queries and config writes.
4. Nginx forwards those requests to the backend dashboard API on `127.0.0.1:18798`.
5. The backend returns JSON payloads used by the React UI.

## Persistence Model

Compose mounts `./data` to `/data`.

Persisted files:

- `router-config.json`: routing, upstream, optional proxy auth, quota, exemption, and profile configuration
- `router-config-auto-proxy-state.json`: auto-proxy activation state
- `router-config-https-interception-state.json`: adaptive HTTPS trust and fallback state
- `https-interception/`: generated local CA and per-host certificates
- `usage.log`: JSONL transfer summaries
- `failures.log`: JSONL failed-request events
- `https-traffic.log`: JSONL intercepted HTTPS request/response analyzer records
- `error.log`: exception details and tracebacks

On backend startup:

- the quota manager reloads usage history from `usage.log`
- the dashboard runtime rebuilds totals and recent entries from `usage.log` and `failures.log`
- the HTTPS traffic cache reads `https-traffic.log` incrementally for dashboard and analyzer API queries
- the auto-proxy manager reloads its persisted state file
- adaptive HTTPS interception reloads trusted-client observations and temporary bypasses

This means the dashboard and routing-related state survive container restarts as long as `./data` is preserved.

## Docker Layout

Docker build files:

- [`Dockerfile`](../Dockerfile): Python backend image
- [`frontend/Dockerfile`](../frontend/Dockerfile): React dashboard + Nginx image

On Linux, Compose runs both containers with host networking:

- the backend can observe host network changes for routing profiles
- the proxy listener binds directly on host port `8900`
- the dashboard frontend binds directly on host port `8798`
- the backend dashboard API stays on host loopback `127.0.0.1:18798`

## Public Interfaces

### CLI

The backend executable remains:

```bash
./proxy-router
```

### Dashboard API

Important routes:

- `GET /api/dashboard`
- `GET /api/history` with optional `range`, `proxy_type`, `client`, `timezone`, and `timezone_offset_minutes` query parameters
- `GET /api/router-config`
- `POST /api/router-config`
- `GET /api/https-interception/status`
- `GET /api/https-interception/ca.crt`
- `GET /api/https-traffic` with optional `client`, `host`, `method`, `status_code`, `search`, `sort`, `direction`, and `limit` query parameters
- `GET /api/https-traffic/{id}` for one captured request/response record
- `GET /api/failures`
- `POST /api/traffic-data/clear`

### Device Portal

Important proxy-local routes:

- `GET http://proxy.router/`
- `GET http://proxy.router/ca`
- `GET http://proxy.router/ca.crt`
- `GET https://proxy.router/ca-check`
- `GET http://proxy.router/api/client`

### Ports

Common defaults:

- Local backend mixed listener: `8799`
- Local backend dashboard API: `8798`
- Compose proxy listener: `8900`
- Compose published dashboard frontend: `8798`

## Design Notes

- The backend is mostly standard-library Python; HTTPS interception uses `cryptography` for certificate generation and optional body-preview decoders for common HTTP content encodings.
- The dashboard frontend is separate from the backend and consumes JSON APIs.
- The root executable is a thin shim; most backend behavior lives in `proxy_router/`.
- Runtime state is centralized in `AppRuntime` instead of spreading service globals across the codebase.
- Optional proxy authentication supports HTTP Basic `Proxy-Authorization` and SOCKS5 username/password. Anonymous access can remain enabled, and authenticated traffic is logged, limited, and exempted as `user:<username>` while retaining the source IP metadata.
- HTTPS interception uses adaptive fallback: successful TLS handshakes mark a client as CA-trusted, while TLS trust failures temporarily bypass MITM for that client or host and use raw CONNECT.
- Intercepted HTTPS analyzer records are append-only JSONL with a stable request id, route metadata, redacted headers, byte totals, and bounded decoded text body previews so a UI or external AI agent can inspect captured traffic without scraping the dashboard.
- SOCKS5 remains a raw tunnel path for apps that reject user-installed CAs or use certificate pinning.
