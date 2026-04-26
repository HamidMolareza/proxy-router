FROM node:24-alpine AS frontend-build

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim AS backend

WORKDIR /app

COPY proxy-router /app/proxy-router
COPY proxy_router /app/proxy_router

RUN useradd --create-home --home-dir /home/proxy-router --shell /usr/sbin/nologin proxyrouter \
    && chmod +x /app/proxy-router \
    && mkdir -p /data \
    && chown -R proxyrouter:proxyrouter /app /data

USER proxyrouter

EXPOSE 8799 8798

ENTRYPOINT ["/app/proxy-router"]

CMD ["--bind", "0.0.0.0", "--mixed-port", "8799", "--dashboard-bind", "0.0.0.0", "--dashboard-port", "8798", "--router-config-file", "/data/router-config.json", "--usage-log-file", "/data/usage.log", "--failure-log-file", "/data/failures.log"]


FROM nginx:1.29-alpine AS dashboard

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=frontend-build /frontend/dist /usr/share/nginx/html

EXPOSE 8798
