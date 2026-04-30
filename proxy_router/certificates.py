from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except Exception as exc:  # pragma: no cover - exercised only when dependency is missing
    x509 = None
    hashes = None
    serialization = None
    rsa = None
    ExtendedKeyUsageOID = None
    NameOID = None
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None

from .constants import *
from .util import normalize_host


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_chmod(path: Path, mode: int):
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _safe_host_filename(host: str) -> str:
    normalized = normalize_host(host) or "unknown"
    slug = re.sub(r"[^a-zA-Z0-9.-]+", "-", normalized).strip("-")[:80] or "host"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"{slug}-{digest}"


class HttpsCertificateManager:
    def __init__(
        self,
        *,
        ca_cert_file: Path,
        ca_key_file: Path,
        cert_cache_dir: Path,
        ca_common_name: str = DEFAULT_HTTPS_INTERCEPT_CA_COMMON_NAME,
    ):
        self.ca_cert_file = Path(ca_cert_file)
        self.ca_key_file = Path(ca_key_file)
        self.cert_cache_dir = Path(cert_cache_dir)
        self.ca_common_name = str(ca_common_name or DEFAULT_HTTPS_INTERCEPT_CA_COMMON_NAME).strip()
        self._lock = threading.RLock()
        self._ca_cert = None
        self._ca_key = None

    def status(self, settings=None) -> dict:
        enabled = bool((settings or {}).get("enabled", False))
        return {
            "enabled": enabled,
            "available": CRYPTOGRAPHY_IMPORT_ERROR is None,
            "error": str(CRYPTOGRAPHY_IMPORT_ERROR) if CRYPTOGRAPHY_IMPORT_ERROR is not None else None,
            "mode": str((settings or {}).get("mode") or "allowlist"),
            "host_patterns": list((settings or {}).get("host_patterns") or []),
            "bypass_patterns": list((settings or {}).get("bypass_patterns") or []),
            "intercepted_ports": sorted(HTTPS_INTERCEPTION_DEFAULT_PORTS),
            "ca_cert_file": str(self.ca_cert_file),
            "ca_key_file": str(self.ca_key_file),
            "cert_cache_dir": str(self.cert_cache_dir),
            "ca_exists": self.ca_cert_file.exists(),
            "cache_exists": self.cert_cache_dir.exists(),
            "ca_common_name": self.ca_common_name,
        }

    def ca_certificate_pem(self) -> bytes:
        ca_cert, _ = self._ensure_ca()
        return ca_cert.public_bytes(serialization.Encoding.PEM)

    def server_ssl_context(self, host: str) -> ssl.SSLContext:
        cert_file, key_file = self._ensure_leaf_certificate(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        return context

    def _require_crypto(self):
        if CRYPTOGRAPHY_IMPORT_ERROR is not None:
            raise RuntimeError(f"cryptography is required for HTTPS interception: {CRYPTOGRAPHY_IMPORT_ERROR}")

    def _ensure_ca(self):
        self._require_crypto()
        with self._lock:
            if self._ca_cert is not None and self._ca_key is not None:
                return self._ca_cert, self._ca_key

            cert_exists = self.ca_cert_file.exists()
            key_exists = self.ca_key_file.exists()
            if cert_exists != key_exists:
                raise OSError(
                    "HTTPS interception CA is incomplete: both CA certificate and private key files are required"
                )

            if cert_exists and key_exists:
                cert = x509.load_pem_x509_certificate(self.ca_cert_file.read_bytes())
                key = serialization.load_pem_private_key(self.ca_key_file.read_bytes(), password=None)
                self._ca_cert = cert
                self._ca_key = key
                return cert, key

            cert, key = self._generate_ca()
            self.ca_cert_file.parent.mkdir(parents=True, exist_ok=True)
            self.ca_key_file.parent.mkdir(parents=True, exist_ok=True)
            self.ca_cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            _safe_chmod(self.ca_cert_file, 0o644)
            self.ca_key_file.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            _safe_chmod(self.ca_key_file, 0o600)
            self._ca_cert = cert
            self._ca_key = key
            return cert, key

    def _generate_ca(self):
        now = _utc_now()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, self.ca_common_name[:64]),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(private_key=key, algorithm=hashes.SHA256())
        )
        return cert, key

    def _ensure_leaf_certificate(self, host: str) -> tuple[Path, Path]:
        normalized_host = normalize_host(host)
        if not normalized_host:
            raise ValueError("cannot generate an HTTPS interception certificate without a host")

        with self._lock:
            ca_cert, ca_key = self._ensure_ca()
            ca_digest = ca_cert.fingerprint(hashes.SHA256()).hex()[:16]
            stem = f"{_safe_host_filename(normalized_host)}-{ca_digest}"
            cert_file = self.cert_cache_dir / f"{stem}.crt"
            key_file = self.cert_cache_dir / f"{stem}.key"
            if cert_file.exists() and key_file.exists():
                return cert_file, key_file
            if cert_file.exists() != key_file.exists():
                try:
                    cert_file.unlink(missing_ok=True)
                    key_file.unlink(missing_ok=True)
                except OSError:
                    pass

            cert, key = self._generate_leaf_certificate(normalized_host, ca_cert, ca_key)
            self.cert_cache_dir.mkdir(parents=True, exist_ok=True)
            cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            _safe_chmod(cert_file, 0o644)
            key_file.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            _safe_chmod(key_file, 0o600)
            return cert_file, key_file

    def _generate_leaf_certificate(self, host: str, ca_cert, ca_key):
        now = _utc_now()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])])
        try:
            san_value = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san_value = x509.DNSName(host)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san_value]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )
        return cert, key
