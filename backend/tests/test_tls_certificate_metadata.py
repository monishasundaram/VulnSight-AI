from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from app.scanners import tls as tls_module
from app.scanners.tls import inspect_tls


class LocalTlsFixture:
    def __init__(self, certificate: str, private_key: str):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, private_key)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def connector(self, _address: tuple[str, int], timeout: float) -> socket.socket:
        return socket.create_connection(("127.0.0.1", self.port), timeout=timeout)

    def _serve(self) -> None:
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            threading.Thread(target=self._handshake, args=(conn,), daemon=True).start()

    def _handshake(self, conn: socket.socket) -> None:
        try:
            with self.context.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.settimeout(0.2)
                try:
                    tls_conn.recv(1)
                except (OSError, TimeoutError, socket.timeout):
                    pass
        except (ssl.SSLError, OSError, TimeoutError):
            conn.close()

    def close(self) -> None:
        self.stopped.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=1)


def _make_certificate(tmp_path: Path) -> tuple[str, str]:
    executable = shutil.which("openssl")
    if executable is None:
        pytest.skip("OpenSSL executable is required for this local TLS-certificate fixture")
    assert executable is not None
    certificate = str(tmp_path / "fixture.crt")
    private_key = str(tmp_path / "fixture.key")
    subprocess.run(
        [executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", private_key, "-out", certificate, "-subj", "/CN=tls.example.test",
         "-addext", "subjectAltName=DNS:tls.example.test"],
        check=True, capture_output=True, text=True, timeout=20,
    )
    return certificate, private_key


def test_tls_inspector_reads_dates_trust_and_hostname_from_a_local_certificate(tmp_path, monkeypatch):
    certificate, private_key = _make_certificate(tmp_path)
    fixture = LocalTlsFixture(certificate, private_key)
    try:
        trust = ssl.create_default_context()
        trust.load_verify_locations(cafile=certificate)
        monkeypatch.setattr(tls_module.ssl, "create_default_context", lambda: trust)
        resolver = lambda _hostname, _port: ("93.184.216.34",)

        valid = inspect_tls(
            "tls.example.test", 443, {"tls.example.test"}, resolver=resolver,
            connector=fixture.connector, timeout_seconds=3,
        )
        assert valid.reachable is True
        assert valid.certificate_trusted is True
        assert valid.hostname_matches is True
        assert valid.valid_from and valid.valid_until
        assert valid.is_expired is False
        assert valid.is_not_yet_valid is False
        assert valid.negotiated_version in {"TLSv1.2", "TLSv1.3"}
        assert valid.cipher

        mismatch = inspect_tls(
            "wrong.example.test", 443, {"wrong.example.test"}, resolver=resolver,
            connector=fixture.connector, timeout_seconds=3,
        )
        assert mismatch.reachable is True
        assert mismatch.certificate_trusted is False
        assert mismatch.hostname_matches is False
        assert mismatch.error_class == "hostname_mismatch"
    finally:
        fixture.close()
