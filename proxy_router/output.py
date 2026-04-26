from __future__ import annotations

import os
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path

from .constants import (
    COLOR_BLUE,
    COLOR_BOLD,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_MAGENTA,
    COLOR_RESET,
    COLOR_YELLOW,
)


def supports_color(stream) -> bool:
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    return "NO_COLOR" not in os.environ


def colorize(text: str, *styles: str, stream=sys.stdout) -> str:
    if not supports_color(stream):
        return text
    return f"{''.join(styles)}{text}{COLOR_RESET}"


def style_proxy_label(proxy_label: str, stream) -> str:
    palette = {
        "mixed": COLOR_BLUE,
        "http": COLOR_CYAN,
        "https": COLOR_MAGENTA,
        "socks5": COLOR_GREEN,
    }
    return colorize(proxy_label, COLOR_BOLD, palette.get(proxy_label, COLOR_BLUE), stream=stream)


def print_info(message: str):
    print(colorize(message, COLOR_CYAN, stream=sys.stdout))


def print_success(message: str):
    print(colorize(message, COLOR_GREEN, stream=sys.stdout))


def print_warning(message: str):
    print(colorize(message, COLOR_YELLOW, stream=sys.stdout))


def print_section(title: str):
    print(colorize(title, COLOR_BOLD, COLOR_BLUE, stream=sys.stdout))


class DebugLogger:
    def __init__(self, enabled: bool = False, log_file: Path | None = None):
        self.enabled = enabled
        self.log_file = log_file
        self._lock = threading.Lock()
        self._stream = None

        if self.enabled and self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self.log_file.open("a", encoding="utf-8", buffering=1)

    def write(self, proxy_label: str, message: str, *, level: str = "DEBUG"):
        if not self.enabled or self._stream is None:
            return

        timestamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        thread_name = threading.current_thread().name
        line = f"{timestamp} [{level}] [{proxy_label}] [{thread_name}] {message}\n"
        with self._lock:
            self._stream.write(line)
            self._stream.flush()

    def exception(self, proxy_label: str, context: str, exc: Exception):
        self.write(proxy_label, f"{context}: {exc!r}", level="ERROR")
        for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
            for stripped_line in line.rstrip().splitlines():
                self.write(proxy_label, stripped_line, level="TRACE")

    def close(self):
        if self._stream is None:
            return

        with self._lock:
            self._stream.close()
            self._stream = None


DEBUG_LOGGER = DebugLogger()
ERROR_LOGGER = DebugLogger(enabled=True)
RUNTIME_LOG_ENABLED = True


def configure_debug_logger(enabled: bool, log_file: Path | None):
    global DEBUG_LOGGER
    DEBUG_LOGGER.close()
    DEBUG_LOGGER = DebugLogger(enabled=enabled, log_file=log_file)


def configure_error_logger(log_file: Path | None):
    global ERROR_LOGGER
    ERROR_LOGGER.close()
    ERROR_LOGGER = DebugLogger(enabled=True, log_file=log_file)


def debug_log(proxy_label: str, message: str, *, level: str = "DEBUG"):
    DEBUG_LOGGER.write(proxy_label, message, level=level)


def debug_exception(proxy_label: str, context: str, exc: Exception):
    DEBUG_LOGGER.exception(proxy_label, context, exc)
    ERROR_LOGGER.exception(proxy_label, context, exc)


def configure_runtime_logging(enabled: bool):
    global RUNTIME_LOG_ENABLED
    RUNTIME_LOG_ENABLED = enabled


def log_event(proxy_label: str, message: str):
    if RUNTIME_LOG_ENABLED:
        print(
            f"[{style_proxy_label(proxy_label, sys.stderr)}] {message}",
            file=sys.stderr,
            flush=True,
        )
    debug_log(proxy_label, message, level="INFO")
