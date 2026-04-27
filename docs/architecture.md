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
- Display history, routing, quotas, and failure review

## Request Flow

### Proxy traffic

1. A client connects to the mixed or SOCKS5 listener.
2. The backend validates the client and evaluates quota state.
3. Routing rules are resolved from the active config and profile context.
4. The request is sent direct, proxied upstream, or blocked.
5. Usage and failure events are written to persisted log files.
6. Runtime dashboard state is updated in memory.

### Dashboard traffic

1. A browser opens the dashboard frontend.
2. The frontend opens `/api/live` for pushed dashboard snapshots and change notifications.
3. The frontend still uses `/api/*` for filtered history queries and config writes.
4. Nginx forwards those requests to the backend dashboard API on `127.0.0.1:18798`.
5. The backend returns JSON payloads used by the React UI.

## Persistence Model

Compose mounts `./data` to `/data`.

Persisted files:

- `router-config.json`: routing, upstream, quota, exemption, and profile configuration
- `router-config-auto-proxy-state.json`: auto-proxy activation state
- `usage.log`: JSONL transfer summaries
- `failures.log`: JSONL failed-request events
- `error.log`: exception details and tracebacks

On backend startup:

- the quota manager reloads usage history from `usage.log`
- the dashboard runtime rebuilds totals and recent entries from `usage.log` and `failures.log`
- the auto-proxy manager reloads its persisted state file

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
- `GET /api/history`
- `GET /api/router-config`
- `POST /api/router-config`
- `GET /api/failures`
- `POST /api/traffic-data/clear`

### Ports

Common defaults:

- Local backend mixed listener: `8799`
- Local backend dashboard API: `8798`
- Compose proxy listener: `8900`
- Compose published dashboard frontend: `8798`

## Design Notes

- The backend intentionally stays standard-library-only.
- The dashboard frontend is separate from the backend and consumes JSON APIs.
- The root executable is a thin shim; most backend behavior lives in `proxy_router/`.
- Runtime state is centralized in `AppRuntime` instead of spreading service globals across the codebase.
