from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

from .config import RouterConfigManager
from .constants import *
from .dashboard_api import DashboardRequestHandler, ThreadedDashboardServer
from .output import *
from .proxy_server import (
    ProxyRequestHandler,
    RunningDashboard,
    RunningServer,
    Socks5RequestHandler,
    ThreadedMixedProxyServer,
    ThreadedSocks5Server,
    ThreadedTLSHTTPProxyServer,
)
from .runtime import AppRuntime
from .util import *

def build_proxy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="Start proxy listeners on this computer so a phone or another device on the same Wi-Fi can use them.",
        epilog=(
            "Examples:\n"
            "  proxy-router\n"
            "  proxy-router --mixed-port 1080\n"
            "  proxy-router --type mixed --type https\n"
            "  proxy-router --allow-client 192.168.1.50\n"
            "  proxy-router --type https --cert-file cert.pem --key-file key.pem\n\n"
            "  proxy-router usage-analyze\n"
            "  proxy-router usage-analyze /tmp/proxy-router-usage.log\n\n"
            "Notes:\n"
            "  - Phone Wi-Fi settings usually support only an HTTP proxy.\n"
            "  - The mixed listener accepts both HTTP and SOCKS5 on one port.\n"
            "  - HTTPS mode here means a TLS-wrapped HTTP proxy server.\n"
            "  - HTTPS interception is configured in the dashboard and adaptively falls back for clients/apps that reject the CA.\n"
            "  - SOCKS5 is useful for apps or tools that support it directly, even on the mixed port.\n"
            "  - On shared Wi-Fi, prefer --allow-client with your phone IP.\n"
            "  - Usage data is written to /tmp/proxy-router-usage.log by default.\n"
            "  - Intercepted HTTPS analyzer data is written to /tmp/proxy-router-https-traffic.log by default."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--type",
        action="append",
        choices=["mixed", "http", "https", "socks5"],
        dest="proxy_types",
        help="Proxy type to start. Repeat to start more than one. Default: mixed. Legacy http/socks5 selections also use the mixed port.",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="IP address to listen on. Default: 0.0.0.0 (all IPv4 interfaces).",
    )
    parser.add_argument(
        "--mixed-port",
        type=int,
        default=MIXED_DEFAULT_PORT,
        help=f"TCP port for the mixed HTTP + SOCKS5 proxy listener. Default: {MIXED_DEFAULT_PORT}",
    )
    parser.add_argument(
        "--https-port",
        type=int,
        default=HTTPS_DEFAULT_PORT,
        help=f"TCP port for the HTTPS proxy. Default: {HTTPS_DEFAULT_PORT}",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        help="Legacy compatibility alias for the mixed port. If set together with --socks5-port they must match.",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        help="Legacy compatibility alias for the mixed port. If set together with --http-port they must match.",
    )
    parser.add_argument(
        "--allow-client",
        action="append",
        default=[],
        metavar="IP_OR_CIDR",
        help="Allow only the given client IP or CIDR. Repeat to allow multiple entries.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Upstream connect/read timeout in seconds. Default: {DEFAULT_TIMEOUT_SECONDS}",
    )
    parser.add_argument(
        "--cert-file",
        help="Certificate file for --type https.",
    )
    parser.add_argument(
        "--key-file",
        help="Private key file for --type https.",
    )
    parser.add_argument(
        "--https-intercept-ca-cert-file",
        default=str(DEFAULT_HTTPS_INTERCEPT_CA_CERT_PATH),
        help=f"CA certificate file for optional HTTPS interception. Default: {DEFAULT_HTTPS_INTERCEPT_CA_CERT_PATH}",
    )
    parser.add_argument(
        "--https-intercept-ca-key-file",
        default=str(DEFAULT_HTTPS_INTERCEPT_CA_KEY_PATH),
        help=f"CA private key file for optional HTTPS interception. Default: {DEFAULT_HTTPS_INTERCEPT_CA_KEY_PATH}",
    )
    parser.add_argument(
        "--https-intercept-cert-cache-dir",
        default=str(DEFAULT_HTTPS_INTERCEPT_CERT_CACHE_DIR),
        help=f"Per-host certificate cache directory for optional HTTPS interception. Default: {DEFAULT_HTTPS_INTERCEPT_CERT_CACHE_DIR}",
    )
    parser.add_argument(
        "--https-intercept-ca-common-name",
        default=DEFAULT_HTTPS_INTERCEPT_CA_COMMON_NAME,
        help=f"Common Name used when generating the HTTPS interception CA. Default: {DEFAULT_HTTPS_INTERCEPT_CA_COMMON_NAME}",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-request and tunnel logs in addition to the default connection logs.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Keep startup output, but suppress runtime console connection logs.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable detailed redacted debugging and save it to a log file. Implies --verbose.",
    )
    parser.add_argument(
        "--debug-log-file",
        help="Debug log file path. Implies --debug. Default: /tmp/proxy-router-debug-<timestamp>.log",
    )
    parser.add_argument(
        "--usage-log-file",
        default=str(DEFAULT_USAGE_LOG_PATH),
        help=f"Usage log file path for transfer summaries. Default: {DEFAULT_USAGE_LOG_PATH}",
    )
    parser.add_argument(
        "--failure-log-file",
        default=str(DEFAULT_FAILURE_LOG_PATH),
        help=f"Failure log file path for failed requests. Default: {DEFAULT_FAILURE_LOG_PATH}",
    )
    parser.add_argument(
        "--https-traffic-log-file",
        default=str(DEFAULT_HTTPS_TRAFFIC_LOG_PATH),
        help=f"JSONL log file path for intercepted HTTPS request/response summaries. Default: {DEFAULT_HTTPS_TRAFFIC_LOG_PATH}",
    )
    parser.add_argument(
        "--error-log-file",
        default=str(DEFAULT_ERROR_LOG_PATH),
        help=f"Error log file path for exception details and tracebacks. Default: {DEFAULT_ERROR_LOG_PATH}",
    )
    parser.add_argument(
        "--router-config-file",
        default=str(DEFAULT_ROUTER_CONFIG_PATH),
        help=f"Router config file path used by the dashboard API. Default: {DEFAULT_ROUTER_CONFIG_PATH}",
    )
    parser.add_argument(
        "--dashboard-bind",
        default=DASHBOARD_DEFAULT_BIND,
        help=f"Bind address for the dashboard API server. Default: {DASHBOARD_DEFAULT_BIND}",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=DASHBOARD_DEFAULT_PORT,
        help=f"TCP port for the dashboard API server. Default: {DASHBOARD_DEFAULT_PORT}",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the dashboard API server.",
    )
    return parser


def build_usage_analyze_parser(prog_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"{prog_name} usage-analyze",
        description="Analyze transfer totals recorded by proxy-router.",
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default=str(DEFAULT_USAGE_LOG_PATH),
        help=f"Usage log file to analyze. Default: {DEFAULT_USAGE_LOG_PATH}",
    )
    parser.add_argument(
        "--client",
        help="Only include records for the given client IP.",
    )
    parser.add_argument(
        "--type",
        dest="proxy_type",
        choices=["http", "https", "socks5"],
        help="Only include records for one proxy type.",
    )
    return parser


def parse_allowed_networks(values):
    networks = []
    for value in values:
        try:
            if "/" in value:
                networks.append(ipaddress.ip_network(value, strict=False))
            else:
                networks.append(ipaddress.ip_network(f"{value}/32", strict=False))
        except ValueError as exc:
            raise SystemExit(f"Error: invalid --allow-client value '{value}': {exc}") from exc
    return networks

def run_usage_analyze(argv):
    parser = build_usage_analyze_parser(Path(sys.argv[0]).name)
    args = parser.parse_args(argv)
    log_file = resolve_usage_log_path(args.log_file)
    records, invalid_lines = load_usage_records(log_file)

    if args.client:
        records = [record for record in records if record.get("client") == args.client]
    if args.proxy_type:
        records = [record for record in records if record.get("proxy_type") == args.proxy_type]

    if not records:
        print_warning("No usage records matched the requested filters.")
        return

    overall = summarize_usage_records(records)
    print_section("Usage summary")
    print(f"  Log file: {log_file}")
    timestamps = [record.get("timestamp") for record in records if record.get("timestamp")]
    if timestamps:
        print(f"  Time range: {min(timestamps)} -> {max(timestamps)}")
    if invalid_lines:
        print_warning(f"Skipped invalid log lines: {invalid_lines}")
    print_usage_summary("Overall", overall)

    print()
    print_section("By proxy type")
    for proxy_type in sorted({record.get('proxy_type', 'unknown') for record in records}):
        summary = summarize_usage_records(
            [record for record in records if record.get("proxy_type", "unknown") == proxy_type]
        )
        print_usage_summary(proxy_type, summary)

    print()
    print_section("By client")
    clients = sorted({record.get("client", "unknown") for record in records})
    for client in clients:
        summary = summarize_usage_records(
            [record for record in records if record.get("client", "unknown") == client]
        )
        print_usage_summary(client, summary)

    print()
    print_info(
        "HTTP records count request and response bodies. CONNECT and SOCKS5 records count raw tunnel bytes."
    )


def start_dashboard_server(args, runtime: AppRuntime, router_config):
    if args.no_dashboard:
        return None

    server = ThreadedDashboardServer(
        (args.dashboard_bind, args.dashboard_port),
        DashboardRequestHandler,
        runtime=runtime,
        router_config=router_config,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return RunningDashboard(
        bind_ip=args.dashboard_bind,
        port=args.dashboard_port,
        server=server,
        thread=thread,
    )


def build_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def uses_mixed_listener(selected_types) -> bool:
    return any(proxy_type in {"mixed", "http", "socks5"} for proxy_type in selected_types)


def resolve_mixed_port(args, selected_types):
    if not uses_mixed_listener(selected_types):
        return None

    if args.http_port is not None and args.socks5_port is not None and args.http_port != args.socks5_port:
        raise SystemExit(
            "Error: --http-port and --socks5-port now map to the same mixed listener and must use the same value. "
            "Use --mixed-port for the shared port."
        )

    if args.http_port is not None:
        return args.http_port
    if args.socks5_port is not None:
        return args.socks5_port
    return args.mixed_port


def raise_listener_start_error(*, listener_label: str, bind_ip: str, port: int, exc: OSError):
    if getattr(exc, "errno", None) == errno.EADDRINUSE:
        raise SystemExit(
            f"Error: could not start {listener_label} listener on {bind_ip}:{port} because the address is already in use. "
            "Stop the process using that port or choose a different port."
        ) from exc
    raise SystemExit(f"Error: could not start {listener_label} listener on {bind_ip}:{port}: {exc}") from exc


def start_servers(args, allowed_networks, router_config, runtime: AppRuntime):
    selected_types = args.proxy_types or ["mixed"]
    servers = []
    listener_ports = set()

    mixed_port = resolve_mixed_port(args, selected_types)

    if mixed_port is not None:
        listener_ports.add(mixed_port)
        try:
            server = ThreadedMixedProxyServer(
                (args.bind, mixed_port),
                allowed_networks=allowed_networks,
                timeout_seconds=args.timeout,
                verbose=args.verbose,
                debug=args.debug,
                router_config=router_config,
                runtime=runtime,
            )
        except OSError as exc:
            raise_listener_start_error(
                listener_label="mixed proxy",
                bind_ip=args.bind,
                port=mixed_port,
                exc=exc,
            )
        servers.append(
            RunningServer(
                proxy_type="mixed",
                bind_ip=args.bind,
                port=mixed_port,
                compatibility="Works with phone Wi-Fi HTTP proxy settings and SOCKS5 clients on the same port.",
                server=server,
                thread=threading.Thread(target=server.serve_forever, daemon=True),
            )
        )

    if "https" in selected_types:
        if not args.cert_file or not args.key_file:
            raise SystemExit("Error: --type https requires both --cert-file and --key-file.")

        listener_ports.add(args.https_port)
        ssl_context = build_ssl_context(args.cert_file, args.key_file)
        try:
            server = ThreadedTLSHTTPProxyServer(
                (args.bind, args.https_port),
                ProxyRequestHandler,
                ssl_context=ssl_context,
                allowed_networks=allowed_networks,
                timeout_seconds=args.timeout,
                verbose=args.verbose,
                debug=args.debug,
                proxy_label="https",
                router_config=router_config,
                runtime=runtime,
            )
        except OSError as exc:
            raise_listener_start_error(
                listener_label="https proxy",
                bind_ip=args.bind,
                port=args.https_port,
                exc=exc,
            )
        servers.append(
            RunningServer(
                proxy_type="https",
                bind_ip=args.bind,
                port=args.https_port,
                compatibility="Only for clients that support an HTTPS proxy with your certificate.",
                server=server,
                thread=threading.Thread(target=server.serve_forever, daemon=True),
            )
        )

    if "socks5" in selected_types:
        listener_ports.add(args.socks5_port)
        server = ThreadedSocks5Server(
            (args.bind, args.socks5_port),
            Socks5RequestHandler,
            allowed_networks=allowed_networks,
            timeout_seconds=args.timeout,
            verbose=args.verbose,
            debug=args.debug,
            router_config=router_config,
            runtime=runtime,
        )
        servers.append(
            RunningServer(
                proxy_type="socks5",
                bind_ip=args.bind,
                port=args.socks5_port,
                compatibility="Use only in apps or tools that support SOCKS5.",
                server=server,
                thread=threading.Thread(target=server.serve_forever, daemon=True),
            )
        )

    for item in servers:
        item.thread.start()

    return servers, listener_ports


def print_startup_instructions(
    servers,
    allowed_networks,
    client_ips,
    debug_log_path: Path | None,
    usage_log_path: Path | None,
    failure_log_path: Path | None,
    https_traffic_log_path: Path | None,
    error_log_path: Path | None,
    router_config_path: Path,
    https_intercept_ca_cert_path: Path,
    https_intercept_cert_cache_dir: Path,
    dashboard: RunningDashboard | None,
):
    print_section("Proxy listeners")
    for item in servers:
        listener = f"{item.bind_ip}:{item.port}"
        print(f"  {style_proxy_label(item.proxy_type, sys.stdout)}  {colorize(listener, COLOR_BOLD, stream=sys.stdout)}")
        print(f"     {colorize(item.compatibility, COLOR_BLUE, stream=sys.stdout)}")

    if allowed_networks:
        allowed_text = ", ".join(str(network) for network in allowed_networks)
        print_success(f"Allowed clients: {allowed_text}")
    else:
        print_warning("Allowed clients: any device that can reach this address")
        print_warning("Security note: on shared Wi-Fi, prefer --allow-client PHONE_IP")

    mixed_server = next((item for item in servers if item.proxy_type == "mixed"), None)
    http_portal_server = next((item for item in servers if item.proxy_type in {"mixed", "http"}), None)
    if mixed_server:
        print()
        print_section("Phone Wi-Fi setup")
        print(f"  Proxy type: {colorize('Manual / HTTP', COLOR_BOLD, COLOR_CYAN, stream=sys.stdout)}")
        if client_ips:
            print(f"  Host: {colorize(client_ips[0], COLOR_BOLD, COLOR_GREEN, stream=sys.stdout)}")
        else:
            print_warning("  Host: <use this computer's Wi-Fi IPv4 address>")
        print(f"  Port: {colorize(str(mixed_server.port), COLOR_BOLD, COLOR_GREEN, stream=sys.stdout)}")
        if len(client_ips) > 1:
            print_info(f"  Other detected IPv4 addresses: {', '.join(client_ips[1:])}")
        print_info("  The same port also accepts SOCKS5 for apps that support it.")
    if http_portal_server:
        print_info(
            f"  Client self-service portal through the proxy: http://{CLIENT_PORTAL_PRIMARY_HOST}/"
        )
        if client_ips:
            print_info(
                f"  Direct client portal on the listener: http://{client_ips[0]}:{http_portal_server.port}/"
            )

    if client_ips:
        print()
        print_info(f"Detected IPv4 addresses for clients: {', '.join(client_ips)}")
    elif any(item.bind_ip == "0.0.0.0" for item in servers):
        print()
        print_warning("Detected IPv4 addresses for clients: none found automatically")
        print_warning("Use your computer's Wi-Fi IPv4 address as the phone proxy host.")

    if any(item.bind_ip == "127.0.0.1" for item in servers):
        print()
        print_warning("Warning: 127.0.0.1 is only reachable from this machine.")
        print_warning("Use --bind 0.0.0.0 or your LAN IP for phone access.")

    print()
    if RUNTIME_LOG_ENABLED:
        print_info("Connection logs are printed automatically when devices connect or disconnect.")
    else:
        print_info("Runtime console connection logs are disabled.")
    if dashboard is not None:
        print_info(f"Dashboard API: http://{dashboard.bind_ip}:{dashboard.port}")
        if RUNTIME_LOG_ENABLED:
            print_info("Use --quiet if you want to watch the dashboard frontend without runtime console logs.")
    if usage_log_path is not None:
        print_info(f"Usage log file: {usage_log_path}")
        print_info(f"Analyze totals later with: {Path(sys.argv[0]).name} usage-analyze {usage_log_path}")
    if failure_log_path is not None:
        print_info(f"Failure log file: {failure_log_path}")
    if https_traffic_log_path is not None:
        print_info(f"HTTPS traffic JSONL log file: {https_traffic_log_path}")
    if error_log_path is not None:
        print_info(f"Error log file: {error_log_path}")
    print_info(f"Router config file: {router_config_path}")
    print_info(f"HTTPS interception CA certificate: {https_intercept_ca_cert_path}")
    print_info(f"HTTPS interception certificate cache: {https_intercept_cert_cache_dir}")
    if debug_log_path is not None:
        print_info(f"Debug log file: {debug_log_path}")
    print_success("Press Ctrl+C to stop.")



def shutdown_servers(
    servers,
    dashboard: RunningDashboard | None,
    runtime: AppRuntime | None,
    router_config: RouterConfigManager | None = None,
):
    for item in servers:
        try:
            item.server.shutdown()
        finally:
            item.server.server_close()

    if dashboard is not None:
        try:
            dashboard.server.shutdown()
        finally:
            dashboard.server.server_close()

    if runtime is not None:
        runtime.close()
    if router_config is not None:
        router_config.shutdown()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "usage-analyze":
        run_usage_analyze(sys.argv[2:])
        return

    parser = build_proxy_parser()
    args = parser.parse_args()

    if args.debug_log_file:
        args.debug = True
    if args.debug:
        args.verbose = True
    configure_runtime_logging(not args.quiet)

    try:
        ipaddress.ip_address(args.bind)
    except ValueError as exc:
        raise SystemExit(f"Error: invalid --bind address '{args.bind}': {exc}") from exc

    ensure_valid_port(args.mixed_port, "--mixed-port")
    ensure_valid_port(args.https_port, "--https-port")
    if args.http_port is not None:
        ensure_valid_port(args.http_port, "--http-port")
    if args.socks5_port is not None:
        ensure_valid_port(args.socks5_port, "--socks5-port")
    if not args.no_dashboard:
        try:
            ipaddress.ip_address(args.dashboard_bind)
        except ValueError as exc:
            raise SystemExit(f"Error: invalid --dashboard-bind address '{args.dashboard_bind}': {exc}") from exc
        ensure_valid_port(args.dashboard_port, "--dashboard-port")

    if args.timeout <= 0:
        raise SystemExit("Error: --timeout must be greater than 0.")

    debug_log_path = resolve_debug_log_path(args.debug_log_file) if args.debug else None
    usage_log_path = resolve_usage_log_path(args.usage_log_file)
    failure_log_path = resolve_failure_log_path(args.failure_log_file)
    https_traffic_log_path = resolve_https_traffic_log_path(args.https_traffic_log_file)
    error_log_path = resolve_error_log_path(args.error_log_file)
    router_config_path = resolve_router_config_path(args.router_config_file)
    https_intercept_ca_cert_path = resolve_https_intercept_ca_cert_path(args.https_intercept_ca_cert_file)
    https_intercept_ca_key_path = resolve_https_intercept_ca_key_path(args.https_intercept_ca_key_file)
    https_intercept_cert_cache_dir = resolve_https_intercept_cert_cache_dir(args.https_intercept_cert_cache_dir)

    try:
        configure_error_logger(error_log_path)
    except OSError as exc:
        raise SystemExit(f"Error: could not open error log file '{error_log_path}': {exc}") from exc

    try:
        configure_debug_logger(args.debug, debug_log_path)
    except OSError as exc:
        ERROR_LOGGER.close()
        raise SystemExit(f"Error: could not open debug log file '{debug_log_path}': {exc}") from exc

    runtime = AppRuntime()
    runtime.configure_https_interception(
        ca_cert_file=https_intercept_ca_cert_path,
        ca_key_file=https_intercept_ca_key_path,
        cert_cache_dir=https_intercept_cert_cache_dir,
        ca_common_name=args.https_intercept_ca_common_name,
    )
    try:
        runtime.configure_usage_log(usage_log_path)
    except OSError as exc:
        DEBUG_LOGGER.close()
        ERROR_LOGGER.close()
        raise SystemExit(f"Error: could not open usage log file '{usage_log_path}': {exc}") from exc

    try:
        runtime.configure_failure_log(failure_log_path)
    except OSError as exc:
        runtime.close()
        DEBUG_LOGGER.close()
        ERROR_LOGGER.close()
        raise SystemExit(f"Error: could not open failure log file '{failure_log_path}': {exc}") from exc

    try:
        runtime.configure_https_traffic_log(https_traffic_log_path)
    except OSError as exc:
        runtime.close()
        DEBUG_LOGGER.close()
        ERROR_LOGGER.close()
        raise SystemExit(f"Error: could not open HTTPS traffic log file '{https_traffic_log_path}': {exc}") from exc

    runtime.configure_traffic_quota_manager(usage_log_path)
    runtime.rehydrate_dashboard_state()

    try:
        router_config = RouterConfigManager(
            router_config_path,
            change_callback=runtime.notify_dashboard_update,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        runtime.close()
        DEBUG_LOGGER.close()
        ERROR_LOGGER.close()
        raise SystemExit(f"Error: could not load router config file '{router_config_path}': {exc}") from exc

    runtime.attach_router_config(router_config)

    debug_log("system", f"argv={sys.argv!r}", level="INFO")
    debug_log(
        "system",
        "configuration "
        f"bind={args.bind} mixed_port={args.mixed_port} http_port={args.http_port} https_port={args.https_port} "
        f"socks5_port={args.socks5_port} timeout={args.timeout}s verbose={args.verbose} debug={args.debug} "
        f"usage_log={usage_log_path} failure_log={failure_log_path} error_log={error_log_path} router_config={router_config_path} "
        f"https_intercept_ca_cert={https_intercept_ca_cert_path} https_intercept_cert_cache={https_intercept_cert_cache_dir} "
        f"dashboard={args.dashboard_bind}:{args.dashboard_port} dashboard_enabled={not args.no_dashboard} quiet={args.quiet}",
        level="INFO",
    )

    allowed_networks = parse_allowed_networks(args.allow_client)
    client_ips = detect_candidate_client_ips()
    debug_log(
        "system",
        f"allowed_networks={[str(network) for network in allowed_networks]} detected_client_ips={client_ips}",
        level="INFO",
    )

    servers, listener_ports = start_servers(args, allowed_networks, router_config, runtime)
    runtime.self_endpoints.configure(
        bind=args.bind,
        dashboard_bind=args.dashboard_bind,
        dashboard_port=args.dashboard_port,
        dashboard_enabled=not args.no_dashboard,
        client_ips=client_ips,
        listener_ports=listener_ports,
    )

    dashboard = None
    if not args.no_dashboard:
        try:
            dashboard = start_dashboard_server(args, runtime, router_config)
        except OSError as exc:
            print_warning(
                f"Dashboard could not start on {args.dashboard_bind}:{args.dashboard_port}: {exc}"
            )
            debug_exception("dashboard", "failed to start dashboard", exc)

    print_startup_instructions(
        servers,
        allowed_networks,
        client_ips,
        debug_log_path,
        usage_log_path,
        failure_log_path,
        https_traffic_log_path,
        error_log_path,
        router_config_path,
        https_intercept_ca_cert_path,
        https_intercept_cert_cache_dir,
        dashboard,
    )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        shutdown_servers(servers, dashboard, runtime, router_config)
        DEBUG_LOGGER.close()
        ERROR_LOGGER.close()


if __name__ == "__main__":
    main()
