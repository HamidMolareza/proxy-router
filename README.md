# proxy-router

`proxy-router` is a LAN-friendly proxy listener with a React dashboard for routing, quotas, usage history, and failure review.

It is designed for cases where a phone or another device on the same network should send traffic through a computer, while you keep control over which hosts go direct, which go through an upstream proxy, and how much traffic each client can use.

## Highlights

- Mixed HTTP + SOCKS5 listener on one port for simple device setup
- React dashboard for overview, history, routing, quotas, and failures
- Shared and per-network routing profiles
- Automatic direct-failure probing before temporary auto-proxy rules
- Per-client traffic quotas, default quotas, and temporary or permanent exemptions
- Docker-first deployment with persistent state under `./data`
- Standard-library Python backend with a separate React + Vite frontend

## Architecture

- `proxy-router` is the backend executable entrypoint.
- `proxy_router/` contains the Python backend package.
- `frontend/` contains the React dashboard app.
- The backend exposes the dashboard API on `/api/*`.
- The dashboard frontend is served separately and reverse-proxies `/api/*` to the backend.
- Docker uses separate Dockerfiles for the backend and dashboard services

More detail: [docs/architecture.md](docs/architecture.md)

## Quick Start

### Docker (recommended)

```bash
docker compose up -d --build
```

Open:

- Dashboard: `http://127.0.0.1:8798`
- Proxy listener: `127.0.0.1:8901`

If you want to use a phone on the same Wi-Fi:

1. Find this computer's LAN IP address.
2. In the phone Wi-Fi proxy settings, choose a manual HTTP proxy.
3. Set:
   - Host: your computer's LAN IP
   - Port: `8901`

### Local development

Start the backend:

```bash
python3 ./proxy-router --help
./proxy-router \
  --bind 0.0.0.0 \
  --dashboard-bind 127.0.0.1 \
  --mixed-port 8799
```

Start the frontend dev server:

```bash
cd frontend
npm install
npm run dev
```

Local development URLs:

- Proxy listener: `http://127.0.0.1:8799`
- Dashboard frontend: `http://127.0.0.1:5173`
- Dashboard API: `http://127.0.0.1:8798`

## Persistence

Compose mounts `./data` into `/data`, so state survives:

- `docker compose restart`
- `docker compose stop` / `docker compose start`
- `docker compose up -d --build`

Persisted backend files:

- `./data/router-config.json`
- `./data/router-config-auto-proxy-state.json`
- `./data/usage.log`
- `./data/failures.log`
- `./data/error.log`

On startup, the backend rebuilds dashboard totals, recent requests, recent failures, quota history, and auto-proxy state from these persisted files.

To reset stored state completely:

1. Stop the stack.
2. Remove the contents of `./data`.
3. Start the stack again.

## Docker

The Compose stack publishes:

- Proxy listener: `8901`
- Dashboard frontend: `8798`

The backend dashboard API stays internal to Compose on port `8798` and is reverse-proxied by the dashboard container at `/api/*`.

Build files:

- [Dockerfile](Dockerfile) for the Python proxy/API container
- [frontend/Dockerfile](frontend/Dockerfile) for the static React dashboard container

## Routing Model

- `Shared` rules apply on every network.
- Saved routing profiles add network-specific rules on top of `Shared`.
- Profile-specific rules win over shared rules.
- Auto-proxy state is tracked per effective profile.

Typical setup:

- `Company VPN` profile: mark selected domains as `Direct`
- `Home` profile: leave them unmanaged so repeated direct failures can trigger temporary auto-proxy routing

## Dashboard

The dashboard includes five main areas:

- `Overview`: current activity, totals, recent traffic, active clients
- `History`: time-bucketed usage history and top destinations
- `Routing`: upstream settings, rules, routing profiles, auto-proxy controls
- `Quotas`: default client quota, per-client quota rules, exemptions
- `Failures`: recent failures, grouped review, ignore and rule-creation workflows

Current dashboard behaviors:

- Router, profile, quota, and exemption changes sync automatically without a Save button
- `Clear rules` clears only the currently edited scope
- `Export rules` downloads routing-only JSON for shared rules plus saved profiles
- `Ignore` on an automatic rule converts it into a permanent manual `Direct` rule

## Quotas

- Specific client limits override the default client quota.
- Exemptions override both custom and default limits.
- Exemptions support permanent and timed entries such as `2h`.

When a client exceeds quota:

- the current request may finish
- the next request is blocked

Response behavior:

- Browser-style HTTP requests receive an HTML response page
- CONNECT/HTTPS and SOCKS5 traffic receive normal non-HTML proxy rejection behavior

## Useful CLI Options

- `--bind`: backend listener bind address
- `--mixed-port`: mixed HTTP + SOCKS5 listener port
- `--allow-client`: restrict which clients may use the proxy
- `--router-config-file`: router config JSON path
- `--usage-log-file`: usage log path
- `--failure-log-file`: failure log path
- `--error-log-file`: persistent exception log path with traceback details
- `--dashboard-bind`: dashboard API bind address
- `--dashboard-port`: dashboard API port
- `--no-dashboard`: disable the dashboard API

Usage summary:

```bash
python3 ./proxy-router --help
python3 ./proxy-router usage-analyze /tmp/proxy-router-usage.log
```

## Repository Layout

```text
proxy-router/              backend executable shim
proxy_router/              Python backend package
frontend/                  React dashboard app
compose.yaml               local Docker Compose stack
Dockerfile                 backend container image build
frontend/Dockerfile        dashboard container image build
data/                      persisted runtime state when using Compose
docs/                      supporting project documentation
```

## Security Notes

- Binding to `0.0.0.0` exposes the listener to any reachable device unless you restrict clients.
- On shared networks, use `--allow-client` whenever possible.
- Do not commit secrets, private upstream credentials, or runtime data files.

## Validation

```bash
python3 -m py_compile ./proxy-router proxy_router/*.py
python3 ./proxy-router --help
cd frontend && npm install && npm run build
docker compose config
```

## Additional Docs

- [docs/architecture.md](docs/architecture.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [frontend/README.md](frontend/README.md)
