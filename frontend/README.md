# proxy-router dashboard

React + Vite frontend for the `proxy-router` dashboard.

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

## Production image

The frontend container builds the Vite app and serves it with Nginx on port `8798`, while reverse-proxying `/api/*` to the `proxy-router` backend service.
