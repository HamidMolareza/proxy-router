# Contributing

## Development Setup

### Backend

```bash
python3 ./proxy-router --help
./proxy-router \
  --bind 0.0.0.0 \
  --dashboard-bind 127.0.0.1 \
  --mixed-port 8799
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Validation

Run the checks relevant to your changes.

Backend:

```bash
python3 -m py_compile ./proxy-router proxy_router/*.py
python3 ./proxy-router --help
```

Frontend:

```bash
cd frontend
npm run lint
npm run build
```

Docker:

```bash
docker compose config
```

## Project Conventions

- Keep the backend standard-library-only unless there is a strong reason to change that.
- Preserve the public executable name: `proxy-router`.
- Keep Docker persistence under `./data`.
- Update documentation when changing:
  - Docker behavior
  - ports
  - dashboard/API flows
  - config structure
  - quota behavior

## Commit Style

This repo uses Conventional Commits by default, for example:

- `feat: ...`
- `fix: ...`
- `refactor: ...`
- `docs: ...`

## Security

- Never commit secrets, tokens, or `.env` files.
- Do not commit runtime data from `./data`.
- Prefer `--allow-client` when testing on shared networks.
