from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import socket
import ssl
from threading import Event
from time import monotonic
from typing import Callable

from app.scanners.budget import RequestBudget, ScanBudgetExceeded
from app.scanners.scope import Resolver, ScopeError, resolve_public_addresses, validate_public_ip


Connector = Callable[[tuple[str, int], float], socket.socket]


@dataclass(frozen=True)
class TLSAssessment:
    hostname: str
    port: int
    reachable: bool
    certificate_trusted: bool | None
    hostname_matches: bool | None
    valid_from: str | None
    valid_until: str | None
    is_expired: bool | None
    is_not_yet_valid: bool | None
    negotiated_version: str | None
    cipher: str | None
    error_class: str | None
    limitation: str = "A single handshake does not test every supported TLS version, cipher or certificate path."

    def to_dict(self) -> dict:
        return asdict(self)


def _date_to_iso(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        stamp = ssl.cert_time_to_seconds(raw)
        return datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _fallback_protocol(hostname: str, port: int, pinned_ip: str, connector: Connector,
                       timeout_seconds: int, budget: RequestBudget | None,
                       before_connect: Callable[[], None] | None,
                       cancel_event: Event | None) -> tuple[str | None, str | None]:
    raw: socket.socket | None = None
    secure: ssl.SSLSocket | None = None
    try:
        if cancel_event is not None and cancel_event.is_set():
            return None, None
        if before_connect is not None:
            before_connect()
        if budget is not None:
            budget.reserve()
        raw = connector((pinned_ip, port), timeout_seconds)
        raw.settimeout(timeout_seconds)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        secure = context.wrap_socket(raw, server_hostname=hostname)
        cipher = secure.cipher()
        return secure.version(), cipher[0] if cipher else None
    except (ScanBudgetExceeded, ssl.SSLError, OSError, TimeoutError, socket.timeout):
        return None, None
    finally:
        if secure is not None:
            secure.close()
        elif raw is not None:
            raw.close()


def inspect_tls(
    hostname: str,
    port: int = 443,
    allowed_hostnames: list[str] | tuple[str, ...] | set[str] | None = None,
    *, resolver: Resolver | None = None, connector: Connector | None = None,
    timeout_seconds: int = 5, budget: RequestBudget | None = None,
    before_connect: Callable[[], None] | None = None, cancel_event: Event | None = None,
) -> TLSAssessment:
    allowed = {hostname} if allowed_hostnames is None else set(allowed_hostnames)
    if port != 443 or hostname not in allowed:
        raise ScopeError("TLS inspection requires an explicitly authorized hostname on port 443")
    if timeout_seconds < 1 or timeout_seconds > 20:
        raise ValueError("TLS timeout must be between 1 and 20 seconds")
    if cancel_event is not None and cancel_event.is_set():
        return TLSAssessment(hostname, port, False, None, None, None, None, None, None, None, None, "cancelled")
    resolve = resolver or resolve_public_addresses
    connect = connector or socket.create_connection
    try:
        addresses = resolve(hostname, port)
        if not addresses:
            raise ScopeError("Hostname has no public addresses")
        pinned_ip = validate_public_ip(str(ipaddress.ip_address(addresses[0])))
    except (ScopeError, ValueError):
        return TLSAssessment(hostname, port, False, None, None, None, None, None, None, None, None, "scope_or_dns")
    raw: socket.socket | None = None
    secure: ssl.SSLSocket | None = None
    try:
        if cancel_event is not None and cancel_event.is_set():
            return TLSAssessment(hostname, port, False, None, None, None, None, None, None, None, None, "cancelled")
        if before_connect is not None:
            before_connect()
        if budget is not None:
            budget.reserve()
        deadline = monotonic() + timeout_seconds
        raw = connect((pinned_ip, port), timeout_seconds)
        raw.settimeout(max(0.05, deadline - monotonic()))
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        secure = context.wrap_socket(raw, server_hostname=hostname)
        cert = secure.getpeercert() or {}
        before_raw = cert.get("notBefore") if isinstance(cert, dict) else None
        after_raw = cert.get("notAfter") if isinstance(cert, dict) else None
        before = _date_to_iso(before_raw if isinstance(before_raw, str) else None)
        after = _date_to_iso(after_raw if isinstance(after_raw, str) else None)
        now = datetime.now(timezone.utc)
        before_dt = datetime.fromisoformat(before) if before else None
        after_dt = datetime.fromisoformat(after) if after else None
        cipher_info = secure.cipher()
        return TLSAssessment(
            hostname=hostname, port=port, reachable=True, certificate_trusted=True, hostname_matches=True,
            valid_from=before, valid_until=after, is_expired=after_dt < now if after_dt else None,
            is_not_yet_valid=before_dt > now if before_dt else None, negotiated_version=secure.version(),
            cipher=cipher_info[0] if cipher_info else None, error_class=None,
        )
    except ScanBudgetExceeded:
        return TLSAssessment(hostname, port, False, None, None, None, None, None, None, None, None, "request_limit")
    except ssl.SSLCertVerificationError as exc:
        message = (exc.verify_message or "").lower()
        if "hostname" in message or "ip address mismatch" in message:
            error_class, host_matches = "hostname_mismatch", False
        elif "expired" in message:
            error_class, host_matches = "expired_certificate", None
        elif "not yet valid" in message:
            error_class, host_matches = "not_yet_valid_certificate", None
        else:
            error_class, host_matches = "untrusted_certificate_chain", None
        version, cipher = _fallback_protocol(hostname, port, pinned_ip, connect, timeout_seconds, budget,
                                             before_connect, cancel_event)
        return TLSAssessment(hostname, port, True, False, host_matches, None, None,
                             error_class == "expired_certificate", error_class == "not_yet_valid_certificate",
                             version, cipher, error_class)
    except (ssl.SSLError, OSError, TimeoutError, socket.timeout):
        return TLSAssessment(hostname, port, False, None, None, None, None, None, None, None, None, "tls_unavailable")
    finally:
        if secure is not None:
            try:
                secure.close()
            except OSError:
                pass
        elif raw is not None:
            try:
                raw.close()
            except OSError:
                pass
