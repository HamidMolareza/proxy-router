FROM python:3.12-slim

WORKDIR /app

COPY proxy-router /app/proxy-router
COPY proxy_router /app/proxy_router
COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir \
    --index-url https://package-mirror.liara.ir/repository/pypi/simple \
    --extra-index-url https://pypi.org/simple \
    -r /app/requirements.txt

RUN useradd --create-home --home-dir /home/proxy-router --shell /usr/sbin/nologin proxyrouter \
    && chmod +x /app/proxy-router \
    && mkdir -p /data \
    && chown -R proxyrouter:proxyrouter /app /data

USER proxyrouter

EXPOSE 8799 8798

ENTRYPOINT ["/app/proxy-router"]

CMD ["--bind", "0.0.0.0", "--mixed-port", "8799", "--dashboard-bind", "0.0.0.0", "--dashboard-port", "8798", "--router-config-file", "/data/router-config.json", "--usage-log-file", "/data/usage.log", "--failure-log-file", "/data/failures.log", "--https-traffic-log-file", "/data/https-traffic.log", "--error-log-file", "/data/error.log", "--https-intercept-ca-cert-file", "/data/https-interception/proxy-router-ca.crt", "--https-intercept-ca-key-file", "/data/https-interception/proxy-router-ca.key", "--https-intercept-cert-cache-dir", "/data/https-interception/certs"]
