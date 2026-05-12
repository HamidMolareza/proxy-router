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
- Display history, upstream proxies, HTTPS traffic analysis, routing, quotas, and failure review

## Request Flow

### Proxy traffic

1. A client connects to the mixed or SOCKS5 listener.
2. The backend validates the source network and resolves an anonymous IP identity or an authenticated `user:<username>` identity.
3. The backend evaluates quota state for that identity.
4. Routing rules are resolved from the active config and profile context.
5. HTTP CONNECT requests are either tunneled unchanged or, when HTTPS interception is enabled and matched, terminated with a generated host certificate.
6. For proxied traffic, the backend selects an allowed upstream proxy by priority, client access policy, and proxy quota state, with failover to the next candidate before returning an error.
7. The request is sent direct, proxied upstream, or blocked.
8. Usage, failure, and intercepted HTTPS analyzer events are written to persisted log files.
9. Runtime dashboard state is updated in memory.

### Dashboard traffic

1. A browser opens the dashboard frontend.
2. The frontend opens `/api/live` for pushed dashboard snapshots and change notifications.
3. The frontend still uses `/api/*` for filtered history queries and config writes.
4. Nginx forwards those requests to the backend dashboard API on `127.0.0.1:18798`.
5. The backend returns JSON payloads used by the React UI.

## Persistence Model

Compose mounts `./data` to `/data`.

Persisted files:

- `router-config.json`: routing, ordered upstream proxy definitions, optional proxy auth, quota, exemption, and profile configuration
- `router-config-auto-proxy-state.json`: auto-proxy activation state
- `router-config-https-interception-state.json`: adaptive HTTPS trust and fallback state
- `router-config-https-discovery-state.json`: unmanaged HTTPS domain discovery and probe state
- `https-interception/`: generated local CA and per-host certificates
- `usage.log`: JSONL transfer summaries, including optional timing, throughput, selected upstream proxy, and failover fields for completed records
- `failures.log`: JSONL failed-request events
- `https-traffic.log`: JSONL intercepted HTTPS request/response analyzer records
- `error.log`: exception details and tracebacks

On backend startup:

- the quota manager reloads client and upstream proxy usage windows from `usage.log`
- the dashboard runtime rebuilds totals and recent entries from `usage.log` and `failures.log`
- the HTTPS traffic cache reads `https-traffic.log` incrementally for dashboard and analyzer API queries
- the auto-proxy manager reloads its persisted state file
- adaptive HTTPS interception reloads trusted-client observations and temporary bypasses
- HTTPS discovery reloads recently probed unmanaged domains to avoid repeated direct/proxy probes

This means the dashboard and routing-related state survive container restarts as long as `./data` is preserved.

## Performance Model

The traffic path records observability at request or tunnel boundaries instead of logging each relayed chunk.

- `duration_ms` is total lifetime for a completed HTTP request, CONNECT tunnel, SOCKS5 tunnel, or WebSocket tunnel.
- `upstream_setup_ms` is the time to open the direct/upstream route and, for normal HTTP/WebSocket requests, receive the upstream response head.
- `relay_ms` is the remaining lifetime after upstream setup and usually represents body or tunnel relay.
- `throughput_bps` is derived from bytes and `duration_ms`; summaries compute it only from records that have timing samples so older logs do not distort rates.
- `upstream_retry_count` and `upstream_retry_delay_ms` show retry attempts and configured backoff time before success or failure.
- `upstream_proxy_id`, `upstream_proxy_name`, and `proxy_failover_count` identify the selected upstream proxy and how many higher-priority candidates were skipped before success.

Expected overhead:

- raw CONNECT and SOCKS5 stay as socket relay paths and only record aggregate timing at completion
- normal HTTP may buffer request bodies when required by existing forwarding behavior
- HTTPS interception adds TLS termination and bounded body-preview capture only for matched hosts
- upstream retries can intentionally add latency before a final success or failure

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
- `GET /api/history` with optional `range`, `proxy_type`, `client`, `upstream_proxy_id`, `timezone`, and `timezone_offset_minutes` query parameters
- `GET /api/history/requests` with optional `client`, `client_ip`, `proxy_type`, `upstream_proxy_id`, `route_label`, `host`, `method`, `status_code`, `search`, `sort`, `direction`, `page`, `page_size`, and `max_results` query parameters
- `GET /api/router-config`
- `POST /api/router-config`
- `POST /api/router-config/preview`
- `GET /api/admin-api/status`
- `POST /api/admin-api/tokens`
- `POST /api/admin-api/tokens/{id}/delete`
- `GET /api/routing/decide` with `host`, optional `client_id`, and optional `client_ip`
- `POST /api/proxies/check`
- `GET /api/https-interception/status`
- `GET /api/https-interception/ca.crt`
- `GET /api/https-traffic` with optional `client`, `host`, `method`, `status_code`, `search`, `sort`, `direction`, and `limit` query parameters
- `GET /api/https-traffic/{id}` for one captured request/response record
- `GET /api/failures`
- `POST /api/traffic-data/clear`

History API notes:

- `/api/history` returns aggregate summaries and period buckets for dashboard charts.
- `/api/history/requests` returns summarized request rows from `usage.log`; it filters before sorting, applies `max_results` before paging, and clamps page sizes to keep MCP and dashboard callers bounded.
- `/api/https-traffic` is separate from request history because it reads intercepted HTTPS analyzer records with request/response metadata from `https-traffic.log`.

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
- Upstream proxies are configured in ordered `proxies[]` entries. Access modes are `public`, `authenticated`, and `private`; private proxies match explicit client identities/IPs/CIDRs, and proxy rules can pin a `proxy_id`. Legacy single-`upstream` config is normalized into one proxy entry for compatibility.
- Automatic direct-failure and HTTPS-discovery proxy assignments persist the selected working proxy id so later requests for that domain reuse the same upstream unless the rule is edited or removed.
- HTTPS interception uses adaptive fallback: successful TLS handshakes mark a client as CA-trusted, while TLS trust failures temporarily bypass MITM for that client or host and use raw CONNECT.
- Intercepted HTTPS analyzer records are append-only JSONL with a stable request id, route metadata, redacted headers, byte totals, and bounded decoded text body previews so a UI or external AI agent can inspect captured traffic without scraping the dashboard.
- HTTPS discovery watches unmanaged direct HTTPS `CONNECT` traffic and probes direct TLS versus upstream TLS in the background. If direct TLS fails and upstream TLS succeeds, it activates the existing temporary auto-proxy rule flow. Raw tunnel completion alone is not treated as proof that the website worked.
- SOCKS5 remains a raw tunnel path for apps that reject user-installed CAs or use certificate pinning.
- Slowdown investigations should start from `usage.log`, `/api/dashboard`, or `/api/history` timing fields before changing relay behavior. Compare route labels, upstream setup time, retries, and throughput for direct versus proxied traffic.
