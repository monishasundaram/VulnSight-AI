from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
import ssl
from time import monotonic
from threading import Event, Lock
from typing import Callable, Any
from urllib.parse import urljoin, urlsplit

from app.scanners.budget import RequestBudget, ScanBudgetExceeded
from app.scanners.scope import Resolver, ScopeError, resolve_public_addresses, validate_public_ip, validate_target_url


HeaderMap = dict[str, str]
Connector = Callable[[tuple[str, int], float], socket.socket]
REDIRECT_CODES = {301, 302, 303, 307, 308}
STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\r\n$")
HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class ScanTransportError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.safe_message = message


@dataclass(frozen=True)
class RedirectHop:
    status_code: int
    source_url: str
    destination: str | None
    followed: bool
    blocked_reason: str | None = None


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    url: str
    headers: HeaderMap
    set_cookie_headers: tuple[str, ...]
    body: bytes
    body_truncated: bool
    redirects: tuple[RedirectHop, ...]
    tls: dict[str, str | bool | None]


class _DeadlineReader:
    def __init__(self, sock: socket.socket, deadline: float, cancel_event: Event | None = None):
        self.sock = sock
        self.deadline = deadline
        self.cancel_event = cancel_event
        self.buffer = bytearray()

    def _fill(self) -> bool:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanTransportError("cancelled", "The scan was cancelled")
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise ScanTransportError("timeout", "The target exceeded the response deadline")
        try:
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
        except (TimeoutError, socket.timeout) as exc:
            raise ScanTransportError("timeout", "The target exceeded the response deadline") from exc
        except OSError as exc:
            raise ScanTransportError("network", "The target response could not be read") from exc
        if not chunk:
            return False
        self.buffer.extend(chunk)
        return True

    def readline(self, maximum: int) -> bytes:
        while True:
            index = self.buffer.find(b"\r\n")
            if index >= 0:
                if index + 2 > maximum:
                    raise ScanTransportError("headers", "The target returned an oversized header line")
                line = bytes(self.buffer[:index + 2])
                del self.buffer[:index + 2]
                return line
            if len(self.buffer) > maximum:
                raise ScanTransportError("headers", "The target returned an oversized header line")
            if not self._fill():
                raise ScanTransportError("protocol", "The target returned an incomplete HTTP response")

    def read(self, count: int) -> bytes:
        result = bytearray()
        if self.buffer:
            take = min(count, len(self.buffer))
            result.extend(self.buffer[:take])
            del self.buffer[:take]
        while len(result) < count:
            if not self._fill():
                break
            take = min(count - len(result), len(self.buffer))
            result.extend(self.buffer[:take])
            del self.buffer[:take]
        return bytes(result)

    def read_to_eof_limited(self, maximum: int) -> tuple[bytes, bool]:
        result = bytearray()
        while len(result) <= maximum:
            if not self._fill():
                return bytes(result), False
            take = min(maximum + 1 - len(result), len(self.buffer))
            result.extend(self.buffer[:take])
            del self.buffer[:take]
            if len(result) > maximum:
                return bytes(result[:maximum]), True
        return bytes(result[:maximum]), True

    def read_exact_limited(self, length: int, maximum: int) -> tuple[bytes, bool]:
        wanted = min(length, maximum + 1)
        result = self.read(wanted)
        truncated = length > maximum or len(result) > maximum
        return result[:maximum], truncated

    def read_chunked_limited(self, maximum: int) -> tuple[bytes, bool]:
        result = bytearray()
        while True:
            line = self.readline(8192).strip()
            try:
                size = int(line.split(b";", 1)[0], 16)
            except ValueError as exc:
                raise ScanTransportError("protocol", "The target returned malformed chunked data") from exc
            if size < 0:
                raise ScanTransportError("protocol", "The target returned malformed chunked data")
            if size == 0:
                total = 0
                while True:
                    trailer = self.readline(8192)
                    total += len(trailer)
                    if total > 16_384:
                        raise ScanTransportError("headers", "The target returned oversized trailers")
                    if trailer == b"\r\n":
                        return bytes(result), False
            if len(result) + size > maximum:
                partial = self.read(maximum + 1 - len(result))
                result.extend(partial[: maximum - len(result)])
                return bytes(result), True
            data = self.read(size)
            if len(data) != size:
                raise ScanTransportError("protocol", "The target returned an incomplete chunk")
            result.extend(data)
            if self.read(2) != b"\r\n":
                raise ScanTransportError("protocol", "The target returned malformed chunk framing")


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port not in (80, 443):
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme}://{netloc}{parsed.path or '/'}"


def _tls_metadata(sock: ssl.SSLSocket) -> dict[str, str | bool | None]:
    peer = sock.getpeercert()
    cert: dict[str, Any] = peer if isinstance(peer, dict) else {}
    cipher_info = sock.cipher()
    return {
        "negotiated_version": sock.version(),
        "cipher": cipher_info[0] if cipher_info else None,
        "certificate_not_before": cert.get("notBefore") if isinstance(cert.get("notBefore"), str) else None,
        "certificate_not_after": cert.get("notAfter") if isinstance(cert.get("notAfter"), str) else None,
        "certificate_hostname_verified": True,
        "certificate_trusted": True,
    }


class SafeHttpClient:
    """Single-GET, response-size- and deadline-bounded transport with DNS pinning and manual redirects."""
    def __init__(self, *, timeout_seconds: int = 8, max_response_bytes: int = 524_288,
                 max_redirects: int = 3, resolver: Resolver | None = None, connector: Connector | None = None,
                 request_budget: RequestBudget | None = None, cancel_event: Event | None = None,
                 before_request: Callable[[], None] | None = None):
        if timeout_seconds < 1 or timeout_seconds > 20:
            raise ValueError("Timeout must be between 1 and 20 seconds")
        if max_response_bytes < 4096 or max_response_bytes > 2_097_152:
            raise ValueError("Response limit must be between 4096 and 2097152 bytes")
        if max_redirects < 0 or max_redirects > 5:
            raise ValueError("Redirect limit must be between 0 and 5")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.resolver = resolver or resolve_public_addresses
        self.connector = connector or socket.create_connection
        self.request_budget = request_budget or RequestBudget(8)
        self.cancel_event = cancel_event
        self.before_request = before_request
        self._active_socket_lock = Lock()
        self._active_socket: socket.socket | None = None

    def cancel(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
        with self._active_socket_lock:
            active = self._active_socket
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                active.close()
            except OSError:
                pass

    def _set_active_socket(self, sock: socket.socket | None) -> None:
        with self._active_socket_lock:
            self._active_socket = sock

    def _single_get(self, url: str, host: str, port: int, allowed: tuple[str, ...], *, allow_query: bool) -> HttpResponse:
        try:
            addresses = self.resolver(host, port)
            if not addresses:
                raise ScopeError("No public address available")
            # Re-check every answer immediately before using the pinned socket destination.
            validated_ips = tuple(validate_public_ip(str(ipaddress.ip_address(ip))) for ip in addresses)
            pinned_ip = validated_ips[0]
            if host not in allowed:
                raise ScopeError("The hostname is outside the approved allowlist")
        except (ScopeError, ValueError) as exc:
            raise ScanTransportError("scope", "The destination is outside the authorized public scope") from exc
        parsed = urlsplit(url)
        request_target = parsed.path or "/"
        if parsed.query:
            if not allow_query or len(parsed.query) > 512:
                raise ScanTransportError("scope", "Only a bounded internal GET probe query is permitted")
            request_target += "?" + parsed.query
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in request_target):
            raise ScanTransportError("scope", "The request path contains an invalid character")
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
        else:
            context = None
        deadline = monotonic() + self.timeout_seconds
        raw: socket.socket | None = None
        secure: ssl.SSLSocket | None = None
        try:
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ScanTransportError("cancelled", "The scan was cancelled")
            if self.before_request is not None:
                self.before_request()
            self.request_budget.reserve()
            raw = self.connector((pinned_ip, port), self.timeout_seconds)
            self._set_active_socket(raw)
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ScanTransportError("cancelled", "The scan was cancelled")
            raw.settimeout(max(0.05, deadline - monotonic()))
            if context is not None:
                secure = context.wrap_socket(raw, server_hostname=host)
                self._set_active_socket(secure)
                sock: socket.socket = secure
            else:
                sock = raw
            host_header = host if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80) else f"{host}:{port}"
            request_bytes = (
                f"GET {request_target} HTTP/1.1\r\nHost: {host_header}\r\n"
                "User-Agent: VulnSight-Audit/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(request_bytes)
            reader = _DeadlineReader(sock, deadline, self.cancel_event)
            status_line = reader.readline(8192)
            match = STATUS_LINE.fullmatch(status_line)
            if match is None:
                raise ScanTransportError("protocol", "The target returned an invalid HTTP status line")
            status = int(match.group(1))
            headers: dict[str, list[str]] = {}
            total_header_bytes = len(status_line)
            header_count = 0
            while True:
                line = reader.readline(8192)
                total_header_bytes += len(line)
                if total_header_bytes > 65_536:
                    raise ScanTransportError("headers", "The target returned oversized HTTP headers")
                if line == b"\r\n":
                    break
                if line[:1] in (b" ", b"\t") or b":" not in line:
                    raise ScanTransportError("protocol", "The target returned malformed HTTP headers")
                header_count += 1
                if header_count > 100:
                    raise ScanTransportError("headers", "The target returned too many HTTP headers")
                name, value = line[:-2].split(b":", 1)
                if not HEADER_NAME.fullmatch(name):
                    raise ScanTransportError("protocol", "The target returned malformed HTTP headers")
                key = name.decode("ascii").lower()
                content = value.decode("latin-1").strip()
                headers.setdefault(key, []).append(content)
            content_lengths = headers.get("content-length", [])
            if len(set(content_lengths)) > 1:
                raise ScanTransportError("protocol", "The target returned conflicting content lengths")
            transfer = ",".join(headers.get("transfer-encoding", [])).lower()
            if content_lengths and transfer:
                raise ScanTransportError("protocol", "The target returned conflicting body framing")
            truncated = False
            if status in (204, 304) or 100 <= status < 200:
                body = b""
            elif "chunked" in transfer:
                body, truncated = reader.read_chunked_limited(self.max_response_bytes)
            elif content_lengths:
                try:
                    content_length = int(content_lengths[0])
                except ValueError as exc:
                    raise ScanTransportError("protocol", "The target returned an invalid content length") from exc
                if content_length < 0:
                    raise ScanTransportError("protocol", "The target returned an invalid content length")
                body, truncated = reader.read_exact_limited(content_length, self.max_response_bytes)
            else:
                body, truncated = reader.read_to_eof_limited(self.max_response_bytes)
            flat_headers = {key: ", ".join(values) for key, values in headers.items() if key != "set-cookie"}
            cookies = tuple(headers.get("set-cookie", ()))
            tls_meta = _tls_metadata(secure) if secure is not None else {}
            return HttpResponse(status, _safe_url(url), flat_headers, cookies, body, truncated, (), tls_meta)
        except ScanBudgetExceeded as exc:
            raise ScanTransportError("request_limit", "The configured scan request limit has been reached") from exc
        except ssl.SSLCertVerificationError as exc:
            raise ScanTransportError("tls_verify", "HTTPS certificate validation failed") from exc
        except ssl.SSLError as exc:
            raise ScanTransportError("tls", "HTTPS negotiation failed") from exc
        except ScanTransportError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise ScanTransportError("timeout", "The target exceeded the response deadline") from exc
        except OSError as exc:
            raise ScanTransportError("network", "The target could not be reached") from exc
        finally:
            self._set_active_socket(None)
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

    def get(self, url: str, allowed_hostnames: list[str] | tuple[str, ...] | set[str], *, allow_query: bool = False,
            follow_redirects: bool = True) -> HttpResponse:
        allowed = tuple(sorted(set(allowed_hostnames)))
        current = url
        redirects: list[RedirectHop] = []
        response: HttpResponse | None = None
        for hop in range(self.max_redirects + 1):
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise ScanTransportError("cancelled", "The scan was cancelled")
            try:
                canonical, host, port, normalized_allowed = validate_target_url(
                    current, allowed, allow_query=allow_query, resolver=self.resolver
                )
            except ScopeError as exc:
                raise ScanTransportError("scope", "A request or redirect fell outside the authorized public scope") from exc
            response = self._single_get(canonical, host, port, normalized_allowed, allow_query=allow_query)
            location = response.headers.get("location")
            if response.status_code not in REDIRECT_CODES or not location or not follow_redirects:
                return HttpResponse(response.status_code, response.url, response.headers, response.set_cookie_headers,
                                    response.body, response.body_truncated, tuple(redirects), response.tls)
            destination = urljoin(canonical, location)
            source_scheme = urlsplit(canonical).scheme
            dest_scheme = urlsplit(destination).scheme
            if source_scheme == "https" and dest_scheme != "https":
                redirects.append(RedirectHop(response.status_code, _safe_url(canonical), _safe_url(destination), False, "https_downgrade"))
                break
            try:
                validate_target_url(destination, normalized_allowed, resolver=self.resolver)
            except ScopeError:
                redirects.append(RedirectHop(response.status_code, _safe_url(canonical), _safe_url(destination), False, "out_of_scope"))
                break
            if hop >= self.max_redirects:
                redirects.append(RedirectHop(response.status_code, _safe_url(canonical), _safe_url(destination), False, "redirect_limit"))
                break
            redirects.append(RedirectHop(response.status_code, _safe_url(canonical), _safe_url(destination), True))
            current = destination
        assert response is not None
        return HttpResponse(response.status_code, response.url, response.headers, response.set_cookie_headers,
                            response.body, response.body_truncated, tuple(redirects), response.tls)
