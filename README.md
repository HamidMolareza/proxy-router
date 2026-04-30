# proxy-router

`proxy-router` is a LAN-friendly proxy listener with a React dashboard for routing, quotas, usage history, and failure review.

It is designed for cases where a phone or another device on the same network should send traffic through a computer, while you keep control over which hosts go direct, which go through an upstream proxy, and how much traffic each client can use.

## Highlights

- Mixed HTTP + SOCKS5 listener on one port for simple device setup
- React dashboard for overview, history, routing, quotas, and failures
- Shared and per-network routing profiles
- Automatic direct-failure probing before temporary auto-proxy rules
- Optional HTTPS request sniffing for allowlisted HTTP CONNECT hosts with an installable local CA
- Per-client traffic quotas, default quotas, and temporary or permanent exemptions
- Docker-first deployment with persistent state under `./data`
- Small Python backend with a separate React + Vite frontend

## Architecture

- `proxy-router` is the backend executable entrypoint.
- `proxy_router/` contains the Python backend package.
- `frontend/` contains the React dashboard app.
- The backend exposes the dashboard API on `/api/*`.
- The dashboard also opens a live WebSocket on `/api/live` for pushed updates.
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
- Proxy listener: `127.0.0.1:8900`

If you want to use a phone on the same Wi-Fi:

1. Find this computer's LAN IP address.
2. In the phone Wi-Fi proxy settings, choose a manual HTTP proxy.
3. Set:
   - Host: your computer's LAN IP
   - Port: `8900`
4. While that proxy is enabled on the device, open `http://proxy.router/` to see a read-only page for that device's own usage, quota status, top destinations, recent requests, and recent failures.
5. To install the HTTPS interception CA on that device, open `http://proxy.router/ca` or use the `Install HTTPS CA` section on the portal.
6. After installing the CA, open `https://proxy.router/ca-check` from the same device to confirm that the browser trusts the proxy-router CA.

### Local development

Start the backend:

```bash
python3 -m pip install -r requirements.txt
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
- `./data/router-config-https-interception-state.json`
- `./data/https-interception/proxy-router-ca.crt`
- `./data/https-interception/proxy-router-ca.key`
- `./data/https-interception/certs/`
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

- Proxy listener: `8900`
- Dashboard frontend: `8798`

On Linux, Compose runs both services with host networking so the backend can observe the real host route and VPN changes for routing profiles.

The backend dashboard API binds only to `127.0.0.1:18798` on the host and is reverse-proxied by the dashboard container at `/api/*`.

Build files:

- [Dockerfile](Dockerfile) for the Python proxy/API container
- [frontend/Dockerfile](frontend/Dockerfile) for the static React dashboard container

Upstream proxy note:

- In the Compose deployment, the backend uses host networking, so a host-side upstream proxy can use `127.0.0.1`.

HTTPS interception note:

- The backend stores the HTTPS interception CA and generated per-host certificates under `./data/https-interception`.
- Adaptive HTTPS trust and fallback observations are stored in `./data/router-config-https-interception-state.json`.
- Only the public CA certificate is exposed through the dashboard/API; the CA private key stays on disk.

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

Client self-service portal:

- Devices using the HTTP proxy can open `http://proxy.router/` to view only their own usage and quota data
- The same page is also available directly on the proxy listener root, for example `http://LAN_IP:8900/`
- Devices can open `http://proxy.router/ca` for Android, Linux, Windows, macOS, and iOS install instructions, and `http://proxy.router/ca.crt` to download the public CA directly
- Devices can open `https://proxy.router/ca-check` after installation to confirm CA trust and clear temporary adaptive bypasses
- This portal is separate from the admin dashboard and does not expose routing or config controls
- The portal uses a Bootstrap-based responsive layout for mobile screens
- The portal uses a filtered WebSocket at `/api/client/live` for live updates scoped to the connected client IP; `proxy.router` pages open the socket against the direct listener address to avoid browser-specific WebSocket proxy handling

Current dashboard behaviors:

- Router, profile, quota, and exemption changes sync automatically without a Save button
- Overview and live dashboard state are pushed over a WebSocket instead of a 2-second polling loop
- Client self-service portal state updates live through WebSocket, with JSON polling only as a fallback if a socket cannot be opened
- Upstream proxy settings run an automatic connectivity check after sync, and the Routing tab shows the latest reachability result plus the last real proxied success or failure
- HTTPS interception can be enabled for all CONNECT port 443 hosts or only allowlisted host patterns, with adaptive fallback for devices/apps that reject the CA
- The device portal includes a Burp-style CA install flow at `http://proxy.router/ca`
- The dashboard shows adaptive HTTPS fallback status, including temporary raw-CONNECT bypasses after TLS trust failures
- Transient upstream connection/setup failures are retried briefly before returning an error to the client. CONNECT and SOCKS5 tunnels are retried before the tunnel opens; regular HTTP retries are limited to safe or empty-body requests.
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
- CONNECT/HTTPS quota rejections return `429 Client Traffic Limit Reached` with `Retry-After` and `X-Proxy-Error*` headers plus a plain-text body
- Some browsers and apps still show a generic tunnel failure for rejected CONNECT requests because HTTPS proxy CONNECT does not have a normal user-visible HTML error page
- SOCKS5 traffic still uses standard SOCKS5 rejection codes without a text body
- Devices can still open the self-service portal at `http://proxy.router/` even while quota-blocked, because that page is served locally by the proxy

## Useful CLI Options

- `--bind`: backend listener bind address
- `--mixed-port`: mixed HTTP + SOCKS5 listener port
- `--allow-client`: restrict which clients may use the proxy
- `--router-config-file`: router config JSON path
- `--usage-log-file`: usage log path
- `--failure-log-file`: failure log path
- `--error-log-file`: persistent exception log path with traceback details
- `--https-intercept-ca-cert-file`: HTTPS interception CA certificate path
- `--https-intercept-ca-key-file`: HTTPS interception CA private key path
- `--https-intercept-cert-cache-dir`: generated per-host certificate cache directory
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
- HTTPS interception decrypts traffic for matched hosts only after the client trusts the local CA; apps with certificate pinning or no user-CA trust are temporarily bypassed after TLS trust failures and can also use manual bypass patterns or SOCKS5.
- Intercepted HTTPS records keep URL-level metadata and byte totals, not headers or bodies.
- Do not commit secrets, private upstream credentials, or runtime data files.

## Validation

```bash
python3 -m py_compile ./proxy-router proxy_router/*.py
python3 -m unittest discover
python3 ./proxy-router --help
cd frontend && npm install && npm run build
docker compose config
```

## Additional Docs

- [docs/architecture.md](docs/architecture.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [frontend/README.md](frontend/README.md)
