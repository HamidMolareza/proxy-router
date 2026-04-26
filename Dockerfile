FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY proxy-router /app/proxy-router
COPY proxy_router /app/proxy_router

RUN useradd --create-home --home-dir /home/proxy-router --shell /usr/sbin/nologin proxyrouter \
    && chmod +x /app/proxy-router \
    && mkdir -p /data \
    && chown -R proxyrouter:proxyrouter /app /data

USER proxyrouter

EXPOSE 8799 8798

ENTRYPOINT ["/app/proxy-router"]

CMD ["--bind", "0.0.0.0", "--mixed-port", "8799", "--dashboard-bind", "0.0.0.0", "--dashboard-port", "8798", "--router-config-file", "/data/router-config.json", "--usage-log-file", "/data/usage.log", "--failure-log-file", "/data/failures.log", "--error-log-file", "/data/error.log"]
