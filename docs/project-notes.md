# Final-year project notes — VulnSight AI

## Abstract

VulnSight AI is an evidence-led defensive web-security assessment application for authorized website owners and students. It combines a React dashboard with a FastAPI backend, an indexed SQLite data model, owner-scoped authentication, a bounded background scanner and downloadable PDF/JSON reports. Its passive checks inspect selected HTTP security headers, cookie security attributes, public HTTP-to-HTTPS behavior, TLS certificate/hostname/negotiation metadata, benign GET reflection and selected response-configuration headers. Every scan is tied to an authorized target with an exact hostname scope; every reported state, finding, progress event and report is derived from backend persistence. The scanner pins validated public DNS addresses, restricts ports, revalidates redirects and bounds network/time/response/job budgets. Synthetic local HTTP/TLS fixtures test intentionally insecure and secure observations without scanning third-party systems. VulnSight is an educational triage aid, not a penetration-testing suite and not a guarantee of application security.

## Problem statement

Small application teams and learners often lack an accessible, explainable workflow for checking common web response misconfigurations. Static demonstrations can create false confidence; unsafe scanners can expose private networks or disrupt systems; and uncontextualized findings can be mistaken for confirmed exploits. The problem is to present evidence-based, repeatable checks with explicit authorization, strict target boundaries, auditable lifecycle state, practical remediation and clear limits.

## Project objectives

1. Provide account registration/login with server-enforced owner isolation, hashed credentials, CSRF and security/audit controls.
2. Store authorized target scope, scan runs, individual progress events, findings, status transitions and report metadata in SQLite.
3. Implement bounded HTTP response-header, cookie, TLS/certificate, redirect, safe-reflection and response-configuration checks.
4. Prevent SSRF through public-address checks, pinned DNS, hostname/port allowlists, redirect revalidation, rate/size/time limits and bounded workers.
5. Derive all dashboard metrics, history, findings and reports from real persisted backend results.
6. Produce downloadable owner-only JSON/PDF reports that explain evidence, remediation, assessment limitations and assumptions.
7. Validate functionality using an injected, local-only known-configuration HTTP server, TLS-certificate fixtures and automated tests.

## Methodology

The implementation was developed in phases: (1) approved architecture, schema, responsive route shell and health endpoint; (2) accounts, sessions, CSRF, audit events, exact-scope authorized target CRUD; (3) pure evidence analyzers, a documented configurable category-severity policy, and safe pinned HTTP/TLS transport; (4) database-backed worker lifecycle, progress, findings and cooperative cancellation; (5) owner-scoped dashboard, history, finding triage and soft-archive/restore; (6) real-result report generation, per-user preferences and retention; and (7) documentation, container packaging and regression validation.

The automated test fixture binds a synthetic server only to an ephemeral loopback port. A test-injected resolver maps a test hostname to a public documentation address and a test-only connector directs that validated connection to the local fixture; the production DNS validator still rejects loopback/private addresses. The server returns deliberately missing security headers and cookie attributes and reflects a bounded non-executable GET marker. Tests verify worker requests, persisted findings/progress, cancellation, owner isolation, JSON/PDF output and secret redaction. A separate local TLS certificate test exercises certificate validity/hostname handling without accessing third parties.

## Evaluation evidence

See the exact run commands and counts recorded in the README and the test suite under `backend/tests/` and `frontend/src/pages/*.test.tsx`. The synthetic sample in `docs/sample-synthetic-report.pdf` was generated from the actual worker's completed local HTTP fixture scan. It contains no user environment or third-party website data. Recreate it with the README's explicit export-test command.

## Delimitations and limitations

- Only public HTTP(S) on ports 80/443 and exact authorized host scopes are supported; private/internal targets are intentionally rejected.
- Checks use bounded GET requests. Login states, POST workflows, arbitrary crawling, active exploitation, credential attacks, data extraction, denial-of-service checks and broad OWASP Top 10 testing are not provided.
- Reflected benign markers are only suspected observations; reflection alone does not prove execution or cross-site scripting.
- One sampled response and one TLS handshake do not characterize every route, TLS version, cipher or deployment condition.
- OWASP ZAP is disabled and not configured; no ZAP or complete OWASP coverage is claimed.
- Background workers and the request limiter are process-local in this SQLite edition. In-flight scans are marked interrupted after a process restart rather than resumed; multi-host production scaling requires a durable queue and shared coordination.
- HTTPS/TLS termination and certificates for the VulnSight application itself are supplied by the deployment platform or a trusted reverse proxy. The scanner inspects certificate behavior of a registered target.

## Future enhancement ideas

- Durable multi-process queue and cooperative distributed job cancellation.
- Optional ZAP passive integration after explicit operator configuration, per-scan scope review and additional consent controls.
- Browser-authenticated testing only with an explicit owner-provided safe credential workflow and separately reviewed security policy.
- OWASP ASVS/check mapping, more granular evidence-linked likelihood/impact scoring beyond the current deployment-level category overrides, and team/project collaboration with well-defined shared-resource authorization.
- Trend comparisons and explainable remediation prioritization from sufficient persisted history.
- Multi-database deployment, tenant retention controls and privacy-preserving encrypted report storage.

## Final-year-project presentation outline

1. Title, motivation and intended users.
2. Problem statement: safe, explainable checks versus fake results and unsafe scope.
3. Project goals, requirements and non-goals.
4. System architecture and trust boundaries.
5. Authorization model, session/CSRF and SQLite data model.
6. Scanner allowlist, DNS pinning, redirect/SSRF controls and network budgets.
7. Header/cookie/TLS analyzers and evidence/confidence policy.
8. Worker lifecycle, genuine progress, cancellation and persisted events.
9. Dashboard, finding workflow and report demo.
10. Synthetic local HTTP/TLS test methodology and automated test evidence.
11. Limitations, safe-use disclaimer and privacy/security controls.
12. Conclusion, future work and questions.
