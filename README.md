# proxy-router

`proxy-router` is a LAN-friendly proxy listener with a React dashboard for routing, users, quotas, usage history, and failure review.

It is designed for cases where a phone or another device on the same network should send traffic through a computer, while you keep control over which hosts go direct, which go through an upstream proxy, and how much traffic each client can use.

## Highlights

- Mixed HTTP + SOCKS5 listener on one port for simple device setup
- React dashboard for overview, history, HTTPS analysis, proxies, routing, users, quotas, and failures
- Shared and per-network routing profiles
- Ordered HTTP/SOCKS5 upstream proxy fallback with public, authenticated-only, or private per-client access
- Automatic direct-failure probing before assigning failing domains to a working upstream proxy
- Optional HTTPS request sniffing for allowlisted HTTP CONNECT hosts with an installable local CA and JSONL analyzer logs
- Optional HTTP/SOCKS proxy authentication for stable per-device identities
- Per-user or per-IP temporary/permanent silent blocks from the admin dashboard
- Per-client traffic quotas, per-proxy quotas, proxy-per-user quotas, default quotas, and temporary or permanent exemptions
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
- `./data/router-config-rule-suggestions.json`
- `./data/router-config-auto-proxy-state.json`
- `./data/router-config-https-interception-state.json`
- `./data/router-config-https-discovery-state.json`
- `./data/https-interception/proxy-router-ca.crt`
- `./data/https-interception/proxy-router-ca.key`
- `./data/https-interception/certs/`
- `./data/usage.log`
- `./data/failures.log`
- `./data/https-traffic.log`
- `./data/error.log`

`usage.log` records transfer totals plus optional performance fields such as `duration_ms`, `upstream_setup_ms`, `relay_ms`, `throughput_bps`, upstream retry counts, and selected upstream proxy metadata such as `upstream_proxy_id`, `upstream_proxy_name`, and `proxy_failover_count`. Older records without these fields still load normally; they count toward traffic totals but not duration, throughput, or per-upstream samples.

On startup, the backend rebuilds dashboard totals, recent requests, recent failures, HTTPS traffic analysis, quota history, and auto-proxy state from these persisted files.

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
- `router-config.json` supports `proxies`, an ordered list of upstream HTTP/SOCKS5 proxies. Existing single-`upstream` configs are normalized into one `upstream-default` proxy for compatibility.

HTTPS interception note:

- The backend stores the HTTPS interception CA and generated per-host certificates under `./data/https-interception`.
- Adaptive HTTPS trust and fallback observations are stored in `./data/router-config-https-interception-state.json`.
- HTTPS discovery observations and TLS probe cooldowns are stored in `./data/router-config-https-discovery-state.json`.
- Intercepted HTTPS request/response metadata and bounded body previews are written to `./data/https-traffic.log` as JSONL for dashboard review or external analyzers.
- Only the public CA certificate is exposed through the dashboard/API; the CA private key stays on disk.

## Routing Model

- `Shared` rules apply on every network.
- Saved routing profiles add network-specific rules on top of `Shared`.
- Profile-specific rules win over shared rules.
- Auto-proxy state is tracked per effective profile.
- `action: proxy` rules can optionally pin a `proxy_id`; otherwise the router tries allowed proxies by priority.
- Auto-proxy rules created after direct failures keep the working proxy id, so later requests for the same domain reuse that proxy unless the rule is changed.

Typical setup:

- `Company VPN` profile: mark selected domains as `Direct`
- `Home` profile: leave them unmanaged so repeated direct failures can trigger auto-proxy assignment to the first working allowed proxy

## Dashboard

The dashboard includes eight main areas:

- `Overview`: current activity, totals, recent traffic, active clients
- `History`: time-bucketed usage history, calendar daily/weekly/monthly/yearly totals, per-client usage totals, and top destinations filtered by range, proxy type, client, and upstream proxy
- `Proxies`: ordered upstream proxy definitions, access mode, allowed clients, global and per-user proxy quotas, per-proxy traffic, and per-user proxy traffic windows
- `Routing`: rules, routing profiles, and auto-proxy controls
- `HTTPS`: CA status, adaptive sniffing config, and filterable captured HTTPS request/response analysis
- `Users`: configured proxy-auth users plus observed client identities/IPs, with silent block/unblock controls
- `Quotas`: optional proxy authentication, default client quota, per-client quota rules, exemptions
- `Failures`: recent failures, grouped review, ignore and rule-creation workflows

Client self-service portal:

- Devices using the HTTP proxy can open `http://proxy.router/` to view only their own usage and quota data
- Devices using SOCKS5 can also open `http://proxy.router/`; the proxy serves the same portal locally after the SOCKS connection is established
- The client portal includes the same daily/weekly/monthly/yearly usage totals for the current device alongside range-based history
- The same page is also available directly on the proxy listener root, for example `http://LAN_IP:8900/`
- Devices can open `http://proxy.router/ca` for Android, Linux, Windows, macOS, and iOS install instructions, and `http://proxy.router/ca.crt` to download the public CA directly
- Devices can open `https://proxy.router/ca-check` after installation to confirm CA trust and clear temporary adaptive bypasses
- Authenticated devices can change their own proxy auth password from the portal after entering the current password
- Authenticated devices can suggest routing rules for the currently active profile; conflicting suggestions show the conflicts and require explicit confirmation before they enter the admin queue
- Authenticated devices can cancel/delete individual Rule Suggestions requests they submitted
- Authenticated devices can clear their own Rule Suggestions history; admins can clear the full Rule Suggestions table from the dashboard
- This portal is separate from the admin dashboard and does not expose direct routing or config controls
- The portal uses a Bootstrap-based responsive layout for mobile screens
- The portal uses a filtered WebSocket at `/api/client/live` for live updates scoped to the connected client IP; `proxy.router` pages open the socket against the direct listener address to avoid browser-specific WebSocket proxy handling

Current dashboard behaviors:

- Router, profile, quota, and exemption changes sync automatically without a Save button
- History can be filtered by client identity or IP, so authenticated clients such as `user:phone` can be reviewed separately from anonymous IP-based clients
- Overview and live dashboard state are pushed over a WebSocket instead of a 2-second polling loop
- Overview, History, and recent request tables show timing and throughput from completed requests, including duration, upstream setup time, relay time, upstream retries, and weighted throughput where timing samples exist.
- Client self-service portal state updates live through WebSocket, with JSON polling only as a fallback if a socket cannot be opened
- Proxy settings sync automatically. Proxied requests try allowed proxies in priority order and skip proxies that are unavailable, inaccessible to the client, or over quota.
- The `Proxies` tab shows each upstream proxy's rolling global quota state plus per-client rolling usage for the one-hour, three-hour, and seven-day windows.
- HTTPS interception can be enabled for all CONNECT port 443 hosts or only allowlisted host patterns, with adaptive fallback for devices/apps that reject the CA
- Unmanaged direct HTTPS domains are learned in the background. The router probes direct TLS and upstream TLS without requiring a device CA; if direct fails and upstream succeeds, the existing temporary auto-proxy rule flow is activated.
- The `HTTPS` tab lists intercepted HTTPS requests in a scrollable table with client, method, status, host, size, duration, sorting, and filters. Selecting a request shows copyable redacted request/response headers and body previews, with raw/beauty tabs for JSON and XML bodies.
- Intercepted HTTPS `403 Forbidden` responses on otherwise direct, unmanaged hosts are retried through allowed upstream proxies when auto-proxy is available; a proxy rule is added only if that retry succeeds
- Proxy authentication can be enabled without forcing every device to use it. Anonymous devices keep using IP-based identities, while HTTP Basic or SOCKS5 username/password clients are logged and limited as `user:<username>`.
- The `Users` tab can silently block a `user:<username>`, single IP, or matched configured target for a timed window such as `6h` or permanently with `always`
- The device portal includes a Burp-style CA install flow at `http://proxy.router/ca`
- The dashboard shows adaptive HTTPS fallback and HTTPS discovery status, including temporary raw-CONNECT bypasses after TLS trust failures and learned domain probe outcomes
- Transient upstream connection/setup failures first fail over to the next allowed proxy, then use the configurable retry policy before returning an error to the client. CONNECT and SOCKS5 tunnels are retried before the tunnel opens; regular HTTP retries are limited to safe or empty-body requests.
- Routing rules cannot sync while the effective ruleset has duplicates or enabled overlapping rules with different actions.
- The Routing tab shows authenticated client rule suggestions with requester details, conflicts, approval, and rejection with an optional admin message.
- Approving a suggestion keeps the same rule validation as manual edits, so still-conflicting suggestions must be resolved before approval succeeds.
- `Check conflicts` scans existing enabled rulesets for duplicate rules and conflicting actions.
- `Clear rules` clears only the currently edited scope
- `Export rules` downloads routing-only JSON for shared rules plus saved profiles
- `Ignore` on an automatic rule converts it into a permanent manual `Direct` rule

## Performance Observability

Raw CONNECT and SOCKS5 tunnels stay on the lightweight relay path: the proxy counts bytes and records timing only when the session finishes. Normal HTTP requests also record the time spent opening the upstream/request response head separately from response relay time.

Use these fields when investigating slow traffic:

- `duration_ms`: total request or tunnel lifetime seen by proxy-router
- `upstream_setup_ms`: time spent connecting to the destination or upstream proxy and receiving the upstream response head when applicable
- `relay_ms`: time after upstream setup, usually body or tunnel relay time
- `throughput_bps`: completed bytes per second for records with a duration sample
- `upstream_retry_count` and `upstream_retry_delay_ms`: retry attempts and configured backoff delay before a request succeeded or failed
- `upstream_proxy_id`, `upstream_proxy_name`, and `proxy_failover_count`: selected upstream proxy and how many priority candidates were skipped before success

Diagnosis tips:

- Compare `direct` and `proxy:*` route rows in the dashboard. If only proxied rows are slow, inspect the upstream proxy/VPN and retry settings first.
- High `upstream_setup_ms` with low relay time usually points to DNS/connect/TLS/upstream latency.
- Long `relay_ms` or low `throughput_bps` points to transfer speed, client Wi-Fi, upstream bandwidth, or a long-lived tunnel.
- HTTPS interception can add TLS and body-preview work for matched hosts; raw CONNECT/SOCKS5 avoids that inspection path.
- `python3 ./proxy-router usage-analyze /tmp/proxy-router-usage.log` prints timing samples from the same JSONL data for offline review.

## Quotas

- Client auth credentials can be managed from the `Quotas` tab. When `Allow anonymous devices` is enabled, devices without proxy credentials continue to work normally. Loopback clients from the proxy host (`127.0.0.0/8` and `::1`) are allowed without credentials even when anonymous devices are disabled.
- Authenticated clients use stable `user:<username>` identities for logs, dashboard totals, limits, and exemptions. Usage records also keep the source client IP for troubleshooting.
- The `Users` tab merges configured auth users with client identities/IPs seen in recorded traffic or failures, so you can block the exact client from the same list.
- The Quotas `By client` table is identity-based: authenticated traffic appears under `user:<username>` instead of a separate source IP row.
- Client limit and exemption targets can be `user:<username>`, a single IP address, or a CIDR range.
- The general default quota applies to anonymous clients and to authenticated clients unless a separate authenticated default quota is enabled.
- Specific client limits override both default quotas.
- Exemptions override both custom and default limits.
- Exemptions support permanent and timed entries such as `2h`.

When a client exceeds quota:

- the current request may finish
- the next request is blocked

Response behavior:

- Browser-style HTTP requests receive an HTML response page. The same quota page is available through the proxy at `http://proxy.router/quota`.
- HTTPS page requests can show the same message when HTTPS interception is active and the client trusts the proxy-router CA.
- Raw CONNECT/HTTPS quota rejections return `429 Client Traffic Limit Reached` with `Retry-After`, `X-Proxy-Error*`, and `X-Proxy-Quota-Url` headers plus a plain-text body.
- Some browsers and apps still show a generic tunnel failure for raw CONNECT requests because HTTPS proxy CONNECT does not have a normal user-visible HTML error page.
- SOCKS5 traffic still uses standard SOCKS5 rejection codes without a text body
- Devices can still open the self-service portal at `http://proxy.router/` even while quota-blocked, because that page is served locally by the proxy

When a client is blocked from the `Users` tab:

- future HTTP, CONNECT, and SOCKS5 sessions are dropped silently instead of receiving the quota page
- timed blocks expire automatically
- the client typically only sees a generic connection failure similar to a firewall or closed port

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
- `--https-traffic-log-file`: intercepted HTTPS analyzer JSONL log path
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
- Optional proxy authentication is an identity feature, not a replacement for network restrictions. Keep anonymous access enabled only on networks where unauthenticated devices are expected; loopback clients on the proxy host are always exempt for local workflows.
- Client auth passwords are stored as salted PBKDF2 hashes in `router-config.json`; authenticated users can rotate only their own password from the client portal, and runtime config or data files should not be committed.
- HTTPS interception decrypts traffic for matched hosts only after the client trusts the local CA; apps with certificate pinning or no user-CA trust get host-scoped temporary bypasses after TLS trust failures, while failed CA trust checks or repeated domain failures can temporarily bypass MITM for the whole client.
- HTTPS discovery uses TLS handshakes only, not decrypted request bodies, to compare direct connectivity with upstream connectivity for unmanaged HTTPS domains.
- Intercepted HTTPS analyzer records include redacted headers and bounded text body previews. Sensitive headers and token-like text fields are redacted, common compressed bodies are decoded for preview when possible, binary bodies are omitted, and previews are truncated, but the log can still contain private application data.
- Do not commit secrets, private upstream credentials, or runtime data files.

## Validation

```bash
python3 -m py_compile ./proxy-router proxy_router/*.py
python3 -m unittest discover
python3 ./proxy-router --help
cd frontend && npm install && npm run lint && npm run build
docker compose config
```

## Additional Docs

- [docs/architecture.md](docs/architecture.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [frontend/README.md](frontend/README.md)
