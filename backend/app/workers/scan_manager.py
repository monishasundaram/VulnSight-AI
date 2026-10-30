from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
import threading
from time import monotonic
from typing import Callable
from urllib.parse import urlencode, urlsplit, urlunsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.entities import Finding, Scan, ScanEvent, Target, utcnow
from app.scanners.budget import RequestBudget
from app.scanners.cookies import analyze_cookies
from app.scanners.headers import analyze_security_headers
from app.scanners.safe_http import HttpResponse, SafeHttpClient, ScanTransportError
from app.scanners.scope import Resolver, ScopeError, validate_target_url
from app.scanners.tls import TLSAssessment, inspect_tls
from app.scanners.types import FindingCandidate, Severity, apply_severity_override


class WorkerCapacityError(RuntimeError):
    pass


@dataclass
class _Signals:
    stop: threading.Event = field(default_factory=threading.Event)
    user_cancel: threading.Event = field(default_factory=threading.Event)
    timed_out: threading.Event = field(default_factory=threading.Event)
    scope_revoked: threading.Event = field(default_factory=threading.Event)


class ScanManager:
    """Bounded in-process job executor; scan lifecycle and events are persisted in SQLite."""
    def __init__(self, *, max_workers: int | None = None, resolver: Resolver | None = None,
                 connector: Callable | None = None):
        self.max_workers = max_workers or settings.scan_max_concurrent_jobs
        self.resolver = resolver
        self.connector = connector
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.RLock()
        self._futures: dict[str, Future] = {}
        self._signals: dict[str, _Signals] = {}
        self._clients: dict[str, SafeHttpClient] = {}
        self._recovered = False

    def _get_executor(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="vulnsight-scan")
        return self._executor

    def recover_interrupted_scans(self) -> None:
        """Mark persisted jobs from a previous process failed rather than inventing resumed progress."""
        with self._lock:
            if self._recovered:
                return
            self._recovered = True
        now = utcnow()
        with SessionLocal() as db:
            pending = db.scalars(select(Scan).where(Scan.status.in_(["queued", "running"]))).all()
            for scan in pending:
                scan.status = "failed"
                scan.stage = "interrupted"
                scan.completed_at = now
                scan.error_summary = "The server restarted while this scan was running; start a new scan for a fresh result."
                if scan.started_at:
                    started = scan.started_at.replace(tzinfo=timezone.utc) if scan.started_at.tzinfo is None else scan.started_at
                    scan.duration_seconds = max(0.0, (now - started).total_seconds())
                db.add(ScanEvent(scan_id=scan.id, stage="interrupted", event_type="error",
                                 message="Persisted scan marked failed after a server restart; progress was not simulated."))
            if pending:
                db.commit()

    def submit(self, scan_id: str) -> None:
        with self._lock:
            active = sum(1 for future in self._futures.values() if not future.done())
            if active >= self.max_workers:
                raise WorkerCapacityError("All scan worker slots are occupied")
            signals = _Signals()
            self._signals[scan_id] = signals
            try:
                future = self._get_executor().submit(self._execute, scan_id, signals)
            except Exception:
                self._signals.pop(scan_id, None)
                raise
            self._futures[scan_id] = future
            future.add_done_callback(lambda completed, key=scan_id: self._cleanup(key, completed))

    def _cleanup(self, scan_id: str, future: Future) -> None:
        with self._lock:
            if self._futures.get(scan_id) is future:
                self._futures.pop(scan_id, None)
                self._signals.pop(scan_id, None)
                self._clients.pop(scan_id, None)

    def cancel(self, scan_id: str) -> None:
        with self._lock:
            signals = self._signals.get(scan_id)
            client = self._clients.get(scan_id)
            if signals is not None:
                signals.user_cancel.set()
                signals.stop.set()
        if client is not None:
            client.cancel()

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for future in self._futures.values() if not future.done())

    @staticmethod
    def _event(db: Session, scan: Scan, *, stage: str, message: str, event_type: str = "stage",
               check_key: str | None = None) -> None:
        db.add(ScanEvent(scan_id=scan.id, stage=stage[:80], event_type=event_type[:24],
                         message=message[:300], check_key=check_key))

    @staticmethod
    def _record_candidates(db: Session, scan: Scan, candidates: list[FindingCandidate]) -> int:
        created = 0
        for raw_candidate in candidates:
            candidate = apply_severity_override(raw_candidate, settings.severity_overrides)
            safe_url = candidate.affected_url[:2048]
            fingerprint_material = json.dumps(
                {"title": candidate.title, "category": candidate.category, "url": safe_url},
                sort_keys=True, separators=(",", ":"),
            )
            fingerprint = hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()
            existing = db.scalar(select(Finding.id).where(Finding.scan_id == scan.id, Finding.fingerprint == fingerprint))
            if existing:
                continue
            safe_evidence = json.loads(json.dumps(candidate.safe_evidence(), allow_nan=False, default=str))
            finding = Finding(
                scan_id=scan.id,
                title=candidate.title[:240],
                category=candidate.category[:64],
                severity=candidate.severity,
                affected_url=safe_url,
                description=candidate.description,
                evidence=safe_evidence,
                impact=candidate.impact,
                remediation=candidate.remediation,
                references=list(candidate.references),
                confidence=candidate.confidence,
                verification_status=candidate.verification_status,
                status="open",
                fingerprint=fingerprint,
                detected_at=utcnow(),
            )
            db.add(finding)
            created += 1
            ScanManager._event(db, scan, stage=scan.stage, event_type="finding",
                               message=f"Observed finding recorded: {candidate.title} ({candidate.severity})")
        return created

    def _complete_check(self, scan_id: str, *, check_key: str, stage: str, message: str,
                        candidates: list[FindingCandidate] | None = None) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status not in {"running", "queued"}:
                return
            scan.stage = stage
            scan.checks_completed = min(scan.checks_total, scan.checks_completed + 1)
            self._event(db, scan, stage=stage, message=message, event_type="check", check_key=check_key)
            if candidates:
                self._record_candidates(db, scan, candidates)
            db.commit()

    def _append_event(self, scan_id: str, *, stage: str, message: str, event_type: str = "stage") -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status not in {"queued", "running"}:
                return
            scan.stage = stage
            self._event(db, scan, stage=stage, message=message, event_type=event_type)
            db.commit()

    def _set_running(self, scan_id: str, signals: _Signals) -> tuple[Scan, Target] | None:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status != "queued":
                return None
            target = db.get(Target, scan.target_id)
            if target is None or target.owner_id != scan.initiated_by or not target.enabled or target.authorization_status != "authorized":
                scan.status = "failed"
                scan.stage = "authorization_failed"
                scan.completed_at = utcnow()
                error_message = "The target is disabled or no longer authorized; no scan request was sent."
                scan.error_summary = error_message
                self._event(db, scan, stage=scan.stage, event_type="error", message=error_message)
                db.commit()
                return None
            now = utcnow()
            scan.status = "running"
            scan.stage = "target_scope"
            scan.started_at = now
            scan.checks_total = 8 if scan.profile in {"standard", "advanced"} else 6
            scan.checks_completed = 0
            self._event(db, scan, stage="target_scope", message="Worker started; revalidating authorization and exact hostname scope.", event_type="status")
            db.commit()
            db.refresh(scan)
            db.refresh(target)
            return scan, target

    @staticmethod
    def _hostname_list(target: Target) -> tuple[str, ...]:
        hosts = (target.scope_configuration or {}).get("allowed_hosts", [])
        return tuple(str(host) for host in hosts)

    def _stop_reason(self, signals: _Signals) -> str | None:
        if signals.timed_out.is_set():
            return "timeout"
        if signals.scope_revoked.is_set():
            return "authorization_changed"
        if signals.user_cancel.is_set():
            return "cancelled"
        return None

    def _finish_stopped(self, scan_id: str, signals: _Signals) -> None:
        reason = self._stop_reason(signals)
        if reason is None:
            reason = "cancelled"
        if reason == "timeout":
            status, stage = "failed", "timeout"
            message = "The configured maximum scan duration was reached; remaining checks were not run."
        elif reason == "authorization_changed":
            status, stage = "cancelled", "authorization_changed"
            message = "Scan stopped because its target authorization or exact scope changed."
        else:
            status, stage = "cancelled", "cancelled"
            message = "Scan cancelled; no further requests will be sent."
        now = utcnow()
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status in {"completed", "failed", "cancelled"}:
                return
            scan.status = status
            scan.stage = stage
            scan.completed_at = now
            scan.error_summary = message if status == "failed" or reason == "authorization_changed" else None
            started = scan.started_at.replace(tzinfo=timezone.utc) if scan.started_at.tzinfo is None else scan.started_at
            scan.duration_seconds = max(0.0, (now - started).total_seconds())
            self._event(db, scan, stage=stage, message=message, event_type="status")
            db.commit()

    def _finish_failed(self, scan_id: str, safe_message: str) -> None:
        now = utcnow()
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status in {"completed", "failed", "cancelled"}:
                return
            scan.status = "failed"
            scan.stage = "failed"
            scan.error_summary = safe_message[:500]
            scan.completed_at = now
            started = scan.started_at.replace(tzinfo=timezone.utc) if scan.started_at.tzinfo is None else scan.started_at
            scan.duration_seconds = max(0.0, (now - started).total_seconds())
            self._event(db, scan, stage="failed", message=safe_message, event_type="error")
            db.commit()

    def _current_target_guard(self, scan_id: str, target_id: str, owner_id: str,
                              captured_url: str, captured_hosts: tuple[str, ...], signals: _Signals) -> None:
        if signals.stop.is_set():
            raise ScanTransportError("cancelled", "The scan was cancelled")
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            target = db.get(Target, target_id)
            if scan is None or target is None or scan.initiated_by != owner_id or target.owner_id != owner_id:
                signals.scope_revoked.set()
                signals.stop.set()
                raise ScanTransportError("authorization_changed", "The target authorization changed")
            if scan.cancel_requested:
                signals.user_cancel.set()
                signals.stop.set()
                raise ScanTransportError("cancelled", "The scan was cancelled")
            current_hosts = self._hostname_list(target)
            if (not target.enabled or target.authorization_status != "authorized" or
                    target.base_url != captured_url or tuple(current_hosts) != captured_hosts):
                signals.scope_revoked.set()
                signals.stop.set()
                scan.cancel_requested = True
                db.commit()
                raise ScanTransportError("authorization_changed", "The target authorization or exact scope changed")

    @staticmethod
    def _tls_candidates(assessment: TLSAssessment, affected_url: str) -> list[FindingCandidate]:
        evidence = assessment.to_dict()
        if assessment.error_class == "request_limit":
            return []
        if not assessment.reachable:
            return [FindingCandidate(
                title="HTTPS endpoint could not be established", category="tls", severity="low",
                affected_url=affected_url,
                description="A TLS handshake to the authorized hostname on port 443 did not complete. This observation does not distinguish an intentionally HTTP-only service from an unavailable TLS endpoint.",
                evidence=evidence, impact="Users may lack a protected transport path if this service handles sensitive data.",
                remediation="If HTTPS is intended, configure a reachable TLS listener with a valid certificate and redirect HTTP to HTTPS.",
                references=("https://www.rfc-editor.org/rfc/rfc8446",), confidence="low", verification_status="observed",
            )]
        if assessment.certificate_trusted is False:
            severity = "high" if assessment.error_class in {"hostname_mismatch", "expired_certificate"} else "medium"
            title = "TLS certificate hostname mismatch" if assessment.error_class == "hostname_mismatch" else (
                "TLS certificate is expired" if assessment.error_class == "expired_certificate" else
                "TLS certificate chain could not be trusted"
            )
            return [FindingCandidate(
                title=title, category="tls", severity=severity, affected_url=affected_url,
                description="The system TLS verifier rejected the certificate chain or hostname presented during a pinned connection to the authorized host.",
                evidence=evidence, impact="Browsers and clients may reject the connection or users may be exposed to a certificate impersonation warning.",
                remediation="Install a currently valid certificate whose subject alternative names cover this hostname and whose chain is trusted by standard clients.",
                references=("https://www.rfc-editor.org/rfc/rfc8446",), confidence="high", verification_status="observed",
            )]
        if assessment.is_expired:
            return [FindingCandidate(
                title="TLS certificate is expired", category="tls", severity="high", affected_url=affected_url,
                description="The verified peer certificate is past its notAfter validity date.", evidence=evidence,
                impact="Clients may reject the HTTPS connection.", remediation="Renew and deploy a certificate with a current validity period.",
                references=("https://www.rfc-editor.org/rfc/rfc8446",), confidence="high", verification_status="observed",
            )]
        if assessment.is_not_yet_valid:
            return [FindingCandidate(
                title="TLS certificate is not yet valid", category="tls", severity="medium", affected_url=affected_url,
                description="The verified peer certificate is not yet within its notBefore validity period.", evidence=evidence,
                impact="Clients may reject the HTTPS connection until the certificate becomes valid.",
                remediation="Check certificate issuance/deployment dates and system clocks.",
                references=("https://www.rfc-editor.org/rfc/rfc8446",), confidence="high", verification_status="observed",
            )]
        if assessment.valid_until:
            try:
                expires = datetime.fromisoformat(assessment.valid_until)
                if expires <= datetime.now(timezone.utc) + timedelta(days=30):
                    return [FindingCandidate(
                        title="TLS certificate expires soon", category="tls", severity="low", affected_url=affected_url,
                        description="The verified peer certificate is within 30 days of its notAfter validity date at the time of this scan.", evidence=evidence,
                        impact="An unrenewed certificate may cause HTTPS failures after its expiry.",
                        remediation="Plan renewal before the certificate's recorded notAfter date.",
                        references=("https://www.rfc-editor.org/rfc/rfc8446",), confidence="high", verification_status="observed",
                    )]
            except (ValueError, TypeError):
                pass
        if assessment.negotiated_version in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
            return [FindingCandidate(
                title="Legacy TLS protocol negotiated", category="tls", severity="medium", affected_url=affected_url,
                description="The observed connection negotiated an older TLS protocol version that should be reviewed against current compatibility requirements.", evidence=evidence,
                impact="Older protocol versions may not provide the desired modern transport baseline.",
                remediation="Enable current TLS protocol versions and disable obsolete versions after compatibility testing.",
                references=("https://www.rfc-editor.org/rfc/rfc8996",), confidence="high", verification_status="observed",
            )]
        return []

    @staticmethod
    def _upgrade_candidate(source_url: str, destination: str | None, reason: str, *, title: str,
                           severity: Severity = "medium") -> FindingCandidate:
        return FindingCandidate(
            title=title, category="transport", severity=severity, affected_url=source_url,
            description="The observed HTTP redirect did not provide a verifiable in-scope HTTPS upgrade, or an HTTPS request attempted to downgrade. The scanner did not follow an unsafe or out-of-scope destination.",
            evidence={"source_url": source_url, "redirect_destination": destination, "decision": reason},
            impact="A user-agent may remain on an unencrypted connection or be directed outside the explicitly authorized hostname scope.",
            remediation="Serve a valid HTTPS endpoint and direct HTTP requests to its HTTPS equivalent; keep redirects within the authorized hostname scope.",
            references=("https://datatracker.ietf.org/doc/html/rfc6797",), confidence="medium", verification_status="observed",
        )

    @staticmethod
    def _configuration_candidates(response: HttpResponse) -> list[FindingCandidate]:
        exposed = {key: response.headers[key] for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator") if response.headers.get(key)}
        if not exposed:
            return []
        return [FindingCandidate(
            title="Response discloses server implementation details", category="response_configuration", severity="informational",
            affected_url=response.url,
            description="The response includes one or more server-identification headers. This is an informational observation, not proof that the advertised component is vulnerable.",
            evidence={"observed_headers": exposed}, impact="Detailed version disclosure may assist reconnaissance when combined with other information.",
            remediation="Remove unnecessary product/version headers where practical; do not treat concealment as a substitute for patching.",
            references=("https://owasp.org/www-project-secure-headers/",), confidence="low", verification_status="observed",
        )]

    @staticmethod
    def _reflection_candidate(response: HttpResponse, marker: str) -> list[FindingCandidate]:
        try:
            reflected = marker.encode("ascii") in response.body
        except (UnicodeEncodeError, TypeError):
            reflected = False
        if not reflected:
            return []
        return [FindingCandidate(
            title="Benign query marker appears in response body", category="input_validation", severity="low",
            affected_url=response.url,
            description="A unique, non-executable GET query marker was observed in the response body. Reflection alone does not establish HTML execution, script injection, or exploitability.",
            evidence={"probe_method": "GET", "probe_parameter": "vulnsight_probe", "marker_reflected": True,
                      "body_truncated": response.body_truncated, "response_status": response.status_code},
            impact="If untrusted data is later inserted into an active HTML/script context without contextual output encoding, cross-site scripting may be possible; this check does not test that condition.",
            remediation="Contextually encode untrusted data before rendering and apply an appropriate output-encoding policy. Validate the result with a separate authorized manual review.",
            references=("https://owasp.org/www-community/attacks/xss/",), confidence="medium", verification_status="suspected",
        )]

    def _execute(self, scan_id: str, signals: _Signals) -> None:
        captured = self._set_running(scan_id, signals)
        if captured is None:
            return
        scan, target = captured
        started_monotonic = monotonic()
        deadline_event = signals.timed_out
        client_holder: dict[str, SafeHttpClient] = {}

        def stop_for_deadline() -> None:
            deadline_event.set()
            signals.stop.set()
            client = client_holder.get("client")
            if client is not None:
                client.cancel()

        timer = threading.Timer(settings.scan_max_duration_seconds, stop_for_deadline)
        timer.daemon = True
        timer.start()
        target_id = target.id
        owner_id = scan.initiated_by
        captured_url = target.base_url
        allowed = self._hostname_list(target)
        profile = scan.profile
        initial_url = captured_url
        hostname = urlsplit(captured_url).hostname or ""
        normalized_allowed = allowed
        request_budget = RequestBudget(settings.scan_max_requests)
        response: HttpResponse | None = None
        try:
            self._current_target_guard(scan_id, target_id, owner_id, captured_url, allowed, signals)
            try:
                initial_url, hostname, _, normalized_allowed = validate_target_url(
                    captured_url, allowed, resolver=self.resolver
                )
            except ScopeError:
                self._complete_check(scan_id, check_key="target_scope", stage="target_scope",
                                     message="Target scope failed fresh public-IP and exact-host validation; no scan request was sent.")
                self._finish_failed(scan_id, "The target no longer resolves exclusively to an authorized public address.")
                return
            self._complete_check(scan_id, check_key="target_scope", stage="target_scope",
                                 message="Target owner, authorization state, exact hostname allowlist and public DNS answers were validated.")

            def before_request() -> None:
                if monotonic() - started_monotonic >= settings.scan_max_duration_seconds:
                    signals.timed_out.set()
                    signals.stop.set()
                    raise ScanTransportError("timeout", "The configured maximum scan duration was reached")
                self._current_target_guard(scan_id, target_id, owner_id, captured_url, allowed, signals)

            client = SafeHttpClient(
                timeout_seconds=settings.scan_timeout_seconds,
                max_response_bytes=settings.scan_max_response_bytes,
                max_redirects=settings.scan_max_redirects,
                resolver=self.resolver,
                connector=self.connector,
                request_budget=request_budget,
                cancel_event=signals.stop,
                before_request=before_request,
            )
            client_holder["client"] = client
            with self._lock:
                self._clients[scan_id] = client
            tls_url = urlunsplit(("https", hostname, "/", "", ""))
            self._current_target_guard(scan_id, target_id, owner_id, captured_url, allowed, signals)
            tls = inspect_tls(hostname, 443, normalized_allowed, resolver=self.resolver, connector=self.connector,
                              timeout_seconds=min(settings.scan_timeout_seconds, 10), budget=request_budget,
                              before_connect=before_request, cancel_event=signals.stop)
            if signals.stop.is_set() or tls.error_class == "cancelled":
                self._finish_stopped(scan_id, signals)
                return
            self._complete_check(scan_id, check_key="tls", stage="tls",
                                 message="TLS handshake result recorded; one handshake does not represent every protocol/cipher configuration.",
                                 candidates=self._tls_candidates(tls, tls_url))
            if signals.stop.is_set():
                self._finish_stopped(scan_id, signals)
                return

            try:
                received_response = client.get(initial_url, normalized_allowed)
                response = received_response
                http_message = f"Received HTTP {received_response.status_code} response; response body and cookie values are not persisted."
            except ScanTransportError as exc:
                if exc.kind in {"cancelled", "authorization_changed", "timeout"}:
                    self._finish_stopped(scan_id, signals)
                    return
                http_message = f"HTTP response unavailable ({exc.kind}); safe bounded request did not produce a usable response."
            self._complete_check(scan_id, check_key="http_connectivity", stage="http_connectivity", message=http_message)
            if signals.stop.is_set():
                self._finish_stopped(scan_id, signals)
                return

            redirect_observation: HttpResponse | None = response if urlsplit(initial_url).scheme == "http" else None
            if redirect_observation is None:
                plain_url = urlunsplit(("http", hostname, urlsplit(initial_url).path or "/", "", ""))
                try:
                    redirect_observation = client.get(plain_url, normalized_allowed, follow_redirects=False)
                except ScanTransportError as exc:
                    if exc.kind in {"cancelled", "authorization_changed", "timeout"}:
                        self._finish_stopped(scan_id, signals)
                        return
            redirect_candidates: list[FindingCandidate] = []
            if response is not None:
                for hop in response.redirects:
                    if hop.blocked_reason == "https_downgrade":
                        redirect_candidates.append(self._upgrade_candidate(hop.source_url, hop.destination, hop.blocked_reason,
                                                                           title="HTTPS redirect attempts a downgrade", severity="high"))
                    elif hop.blocked_reason == "out_of_scope":
                        redirect_candidates.append(self._upgrade_candidate(hop.source_url, hop.destination, hop.blocked_reason,
                                                                           title="Redirect leaves the explicitly authorized scope"))
            if redirect_observation is not None:
                status = redirect_observation.status_code
                location = redirect_observation.headers.get("location")
                if status in {301, 302, 303, 307, 308} and location:
                    from urllib.parse import urljoin
                    destination_url = urljoin(redirect_observation.url, location)
                    parsed_destination = urlsplit(destination_url)
                    destination_host = (parsed_destination.hostname or "").lower()
                    safe_destination = urlunsplit((parsed_destination.scheme, parsed_destination.netloc, parsed_destination.path or "/", "", ""))
                    if parsed_destination.scheme == "https" and destination_host in normalized_allowed:
                        pass
                    else:
                        reason = "out_of_scope" if destination_host not in normalized_allowed else "no_https_upgrade"
                        redirect_candidates.append(self._upgrade_candidate(redirect_observation.url, safe_destination, reason,
                                                                           title="HTTP redirect does not upgrade within authorized HTTPS scope"))
                elif 200 <= status < 400 and not location and urlsplit(redirect_observation.url).scheme == "http":
                    redirect_candidates.append(self._upgrade_candidate(redirect_observation.url, None, "no_https_redirect",
                                                                       title="HTTP endpoint did not redirect to HTTPS"))
            self._complete_check(scan_id, check_key="https_redirect", stage="https_redirect",
                                 message="HTTP-to-HTTPS behavior observed; unsafe/out-of-scope redirects were not followed." if redirect_observation else
                                         "HTTP endpoint unavailable; upgrade behavior could not be determined.",
                                 candidates=redirect_candidates)
            if signals.stop.is_set():
                self._finish_stopped(scan_id, signals)
                return

            header_candidates = analyze_security_headers(response.headers, response.url) if response else []
            self._complete_check(scan_id, check_key="security_headers", stage="security_headers",
                                 message="Security response header policy assessed from the observed HTTP response." if response else
                                         "Header analysis skipped because no usable HTTP response was received.", candidates=header_candidates)
            if signals.stop.is_set():
                self._finish_stopped(scan_id, signals)
                return

            cookie_candidates = analyze_cookies(response.set_cookie_headers, response.url) if response else []
            self._complete_check(scan_id, check_key="cookies", stage="cookies",
                                 message="Cookie flag metadata assessed; cookie values were not added to findings." if response else
                                         "Cookie analysis skipped because no usable HTTP response was received.", candidates=cookie_candidates)
            if signals.stop.is_set():
                self._finish_stopped(scan_id, signals)
                return

            if profile in {"standard", "advanced"}:
                reflection_candidates: list[FindingCandidate] = []
                if response is not None and request_budget.remaining > 0:
                    marker = secrets.token_hex(8)
                    parsed = urlsplit(response.url)
                    probe_query = urlencode({"vulnsight_probe": marker})
                    probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", probe_query, ""))
                    try:
                        probe_response = client.get(probe_url, normalized_allowed, allow_query=True, follow_redirects=False)
                        reflection_candidates = self._reflection_candidate(probe_response, marker)
                        reflection_message = "A bounded non-executable GET marker probe completed; the marker itself was not persisted."
                    except ScanTransportError as exc:
                        if exc.kind in {"cancelled", "authorization_changed", "timeout"}:
                            self._finish_stopped(scan_id, signals)
                            return
                        reflection_message = f"Benign GET marker probe unavailable ({exc.kind}); no exploit payload was sent."
                else:
                    reflection_message = "Benign GET marker probe skipped because no response or request budget was available."
                self._complete_check(scan_id, check_key="safe_input_reflection", stage="safe_input_reflection",
                                     message=reflection_message, candidates=reflection_candidates)
                if signals.stop.is_set():
                    self._finish_stopped(scan_id, signals)
                    return

                config_candidates = self._configuration_candidates(response) if response else []
                self._complete_check(scan_id, check_key="response_configuration", stage="response_configuration",
                                     message="Response implementation-identification headers were assessed." if response else
                                             "Response configuration check skipped because no usable response was received.",
                                     candidates=config_candidates)
                if profile == "advanced":
                    self._append_event(scan_id, stage="optional_zap", event_type="limitation",
                                       message="OWASP ZAP is unavailable in this installation; advanced profile remained passive and made no active scan.")

            if signals.stop.is_set():
                self._finish_stopped(scan_id, signals)
                return
            now = utcnow()
            with SessionLocal() as db:
                current_scan = db.get(Scan, scan_id)
                if current_scan is None or current_scan.status != "running":
                    return
                if current_scan.cancel_requested:
                    signals.user_cancel.set()
                    signals.stop.set()
                    self._finish_stopped(scan_id, signals)
                    return
                current_scan.status = "completed"
                current_scan.stage = "completed"
                current_scan.completed_at = now
                started = current_scan.started_at.replace(tzinfo=timezone.utc) if current_scan.started_at.tzinfo is None else current_scan.started_at
                current_scan.duration_seconds = max(0.0, (now - started).total_seconds())
                findings_count = db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0
                self._event(db, current_scan, stage="completed", event_type="status",
                            message=f"Scan completed: {current_scan.checks_completed}/{current_scan.checks_total} checks recorded; {findings_count} findings persisted.")
                current_target = db.get(Target, target_id)
                if current_target is not None:
                    current_target.last_scan_at = now
                db.commit()
        except ScanTransportError as exc:
            if exc.kind in {"cancelled", "authorization_changed", "timeout"}:
                if exc.kind == "authorization_changed":
                    signals.scope_revoked.set()
                elif exc.kind == "timeout":
                    signals.timed_out.set()
                self._finish_stopped(scan_id, signals)
            else:
                self._finish_failed(scan_id, "The scan could not safely complete. Review the persisted events and start a new scan if appropriate.")
        except Exception:
            # Do not persist or print exception text, which may contain target data.
            self._finish_failed(scan_id, "An internal scan error interrupted completion; sensitive request and cookie data were not persisted.")
        finally:
            timer.cancel()
            with self._lock:
                self._clients.pop(scan_id, None)
