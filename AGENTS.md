# AGENTS.md

These instructions apply to this standalone `proxy-router` project.

## Project shape

- The main application is the root executable: `proxy-router`
- Keep the project lightweight and single-file unless a split is clearly necessary
- Prefer standard-library Python only

## Editing

- Preserve the current command name: `proxy-router`
- Keep dashboard/backend behavior in sync when changing config fields
- Prefer minimal, focused changes over broad refactors
- Use ASCII unless the file already needs something else

## Validation

- Run `python3 -m py_compile ./proxy-router`
- Run `python3 ./proxy-router --help`
- For container changes, run `docker compose config` when Docker is available

## Docker

- Use `docker compose`, not `docker-compose`
- Keep runtime data mounted under `./data`
- Do not bake secrets into the image or commit `.env`

## Performance and observability

- Treat traffic slowdown as a first-class concern when changing relay, routing, retry, HTTPS interception, quota, or logging behavior.
- Preserve the lightweight raw CONNECT and SOCKS5 relay path; do not add per-chunk logging, body inspection, or blocking dashboard work to that path.
- Use `usage.log`, `/api/dashboard`, and `/api/history` timing fields before refactoring traffic code: `duration_ms`, `upstream_setup_ms`, `relay_ms`, `throughput_bps`, `upstream_retry_count`, and `upstream_retry_delay_ms`.
- When analyzing slow logs, compare direct versus `proxy:*` route labels, check whether time is in upstream setup or relay, and account for intentional upstream retry delay.
- Keep old usage logs compatible. Missing timing fields mean no timing sample, not zero duration.
- Update README, architecture docs, frontend tables, and tests when adding or changing performance fields.

## Docs

- Update `README.md` when changing dashboard flows, config structure, ports, Docker usage, or quota behavior
