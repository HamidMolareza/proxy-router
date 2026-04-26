# proxy-router

`proxy-router` is a standalone single-file Python proxy router with:

- a mixed HTTP + SOCKS5 listener
- an optional dashboard
- shared and per-network routing profiles
- automatic direct-failure probing before temporary auto-proxy rules
- per-client traffic quotas, default quotas, and temporary/permanent quota exemptions

## Run locally

```bash
python3 ./proxy-router --help
./proxy-router \
  --bind 0.0.0.0 \
  --dashboard-bind 127.0.0.1 \
  --mixed-port 8799
```

Useful paths on the host:

- router config: `~/.config/proxy-router/router-config.json`
- usage log: `/tmp/proxy-router-usage.log`
- failure log: `/tmp/proxy-router-failures.log`

## Docker

Build and run with Compose:

```bash
docker compose up -d --build
```

Default container ports:

- proxy listener: `8799`
- dashboard: `8798`

Compose mounts `./data` into `/data` and passes explicit file paths:

- `/data/router-config.json`
- `/data/usage.log`
- `/data/failures.log`

## Routing model

- `Shared` rules apply to every detected network profile.
- Profile-specific rules are added on top of `Shared`.
- Profile-specific rules win over shared rules.
- Auto-proxy state is profile-specific.

Typical example:

- `Company VPN` profile: add Telegram domains as `Direct`
- `Home` profile: no direct rule, so repeated direct failures can trigger proxy probing and then temporary auto-proxy

## Rules and dashboard

- The dashboard uses tabs for overview, history, routing, quotas, and failures.
- `Clear rules` clears only the currently edited scope.
- `Export rules` downloads routing-only JSON for shared rules plus all saved profiles.
- `Ignore` on an auto rule converts it into a permanent manual `Direct` rule.

## Quotas

- Specific client limits override the default device quota.
- Exemptions override both custom and default limits.
- Use exemptions for:
  - permanent exclusions like `127.0.0.1`
  - temporary suspension such as `2h`

When a quota is crossed, the current request may finish and the next request is blocked.

For browser-style HTTP requests, quota blocks return an HTML page. For CONNECT/HTTPS and SOCKS5 traffic, the proxy returns a normal non-HTML rejection.

## Validation

```bash
python3 -m py_compile ./proxy-router
python3 ./proxy-router --help
```
