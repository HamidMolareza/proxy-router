# proxy-router dashboard

React + Vite frontend for the `proxy-router` dashboard.

This app is developed locally from the `frontend/` directory, but for Docker deployments it is built from the single root `Dockerfile` using the `dashboard` target.

## Local development

```bash
npm install
npm run dev
```

The Vite dev server proxies `/api/*` to `http://127.0.0.1:8798` by default.

Override the backend origin if needed:

```bash
VITE_BACKEND_ORIGIN=http://127.0.0.1:18798 npm run dev
```

Useful local URLs:

- frontend dev server: `http://127.0.0.1:5173`
- backend dashboard API: `http://127.0.0.1:8798`

## Production build

The production dashboard is served by Nginx and reverse-proxies `/api/*` to the `proxy-router` backend service.

Docker note:

- there is no separate `frontend/Dockerfile`
- the dashboard image is built from the repository root `Dockerfile`
- Compose uses the `dashboard` build target
