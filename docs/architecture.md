# VulnSight AI — Architecture

## Runtime shape

VulnSight is a same-origin full-stack application. React 19, TypeScript, Vite and React Router render all dashboard and management routes. Vite bundles the frontend into `backend/app/static`; FastAPI serves that static output and owns `/api/*`, health, OpenAPI and the route manifest. The development frontend can alternatively run on Vite port 5173 and proxy relative `/api` requests to FastAPI on port 3000.

FastAPI authenticates users with Argon2id password hashes and opaque, random server-side session identifiers stored as hashes in SQLite. A per-session CSRF token is paired with the `HttpOnly` cookie. Each API derives the owner from the authenticated server context; request-supplied owner IDs are not trusted. The public HTTPS Preview configuration uses `Secure; SameSite=None`; local plain HTTP uses a separate explicit `Secure=false; SameSite=Lax` override.

Targets require explicit authorization, an exact normalized hostname allowlist, a public DNS answer and a standard HTTP(S) port (80 or 443). Production DNS resolution rejects loopback, private, link-local, multicast, reserved and metadata addresses. A scanner request resolves and pins an approved address, carries no browser credentials, bounds each response and request budget, and revalidates every redirect before it can be followed. Test-only loopback access exists exclusively through injected test resolvers/connectors; it does not relax the production validator.

The scan manager uses bounded worker threads and persisted SQLite status/events. A queued scan becomes running only when a worker starts. Each completed stage/check and finding is written to the database and exposed by the API; elapsed time is calculated from the persisted start timestamp. Cancellation closes the active socket where possible, prevents later requests and records its state. On application restart, unfinished jobs are marked interrupted/failed rather than shown as simulated progress; this single-process edition does not claim a durable external queue.

The analyzers inspect HTTP response headers, cookie attributes, HTTPS redirect behavior, the negotiated TLS handshake/certificate, one harmless GET reflection marker (Standard/Advanced only) and selected implementation-identification headers. Findings carry evidence, confidence and an `observed`/`suspected` verification status. Missing headers and cookie flags are contextual observations, not claimed proof of compromise. No active exploit, authentication test, credential guessing, data extraction, DoS or configured ZAP integration is provided.

Reports are generated from persisted owner-scoped scan/finding records. JSON/PDF contents and metadata are recorded in SQLite; private artifact files are written under the configured data directory with restrictive permissions, hashes and atomic writes. Reports are owner-checked on generation, preview and download. Expired report files are pruned lazily when the owner's Reports API is next read, with an audit event.

## Request, scan-job and cancellation flow

```mermaid
sequenceDiagram
    actor User
    participant UI as React UI
    participant API as FastAPI
    participant DB as SQLite
    participant Worker as bounded scan worker
    participant Target as explicitly authorized public target
    User->>UI: confirm exact URL, profile and authorization
    UI->>API: POST /api/scans + session cookie + CSRF token
    API->>DB: verify owner/scope; persist queued Scan, event and audit record
    API->>Worker: submit persisted scan ID (bounded queue)
    Worker->>DB: persist running state and actual check events
    Worker->>Target: pinned bounded HTTP/TLS requests; revalidate redirects
    Target-->>Worker: sampled headers, TLS metadata and bounded body
    Worker->>DB: persist evidence-backed findings/check progress
    UI->>API: poll owner-scoped scan/events; render actual persisted state
    User->>UI: cancel active scan
    UI->>API: POST /api/scans/{id}/cancel + CSRF token
    API->>Worker: set cooperative cancellation and close active socket
    Worker->>DB: persist cancellation; send no later requests
    API-->>UI: terminal scan, findings, limits and event history
```

## Main source layout

| Path | Responsibility |
| --- | --- |
| `frontend/src/App.tsx` | Public auth routes and guarded application route table. |
| `frontend/src/layouts/AppShell.tsx` | Responsive navigation, user session, saved theme bootstrap. |
| `frontend/src/pages/` | API-connected dashboard, target CRUD, scan wizard/progress/history, vulnerability/finding details, reports, settings and help. |
| `frontend/src/services/api.ts` | Same-origin typed API transport, CSRF and safe error mapping. |
| `backend/app/main.py` | FastAPI lifecycle, scanner application security headers, safe exception handlers, static/route-manifest serving and API assembly. |
| `backend/app/api/` | Authentication, dashboard, target, scan, finding, report and settings endpoints and Pydantic input contracts. |
| `backend/app/core/` | Validated environment settings, Argon2 password handling, hashed sessions, CSRF, ownership context, audit and bounded rate limiting. |
| `backend/app/models/entities.py` | SQLAlchemy tables, constraints, relationships and indexes. |
| `backend/app/scanners/` | Public-scope validation, request/TLS budgets, pinned safe HTTP transport and header/cookie/TLS analyzers. |
| `backend/app/workers/scan_manager.py` | In-process bounded job scheduler, persistence, progress events and cooperative cancellation. |
| `backend/app/api/reports.py` | Owner-scoped real-result report serialization, PDF/JSON generation, integrity and download safety. |
| `backend/migrations/versions/` | Forward-only Alembic migration history. |
| `backend/tests/` | Isolated SQLite, API/authz, local synthetic HTTP/TLS, scanner and report tests. |

## SQLite entity model

```mermaid
erDiagram
    USERS ||--o{ AUTH_SESSIONS : authenticates
    USERS ||--o{ TARGETS : owns
    USERS ||--o{ SCANS : initiates
    TARGETS ||--o{ SCANS : assessed_by
    SCANS ||--o{ SCAN_EVENTS : records
    SCANS ||--o{ FINDINGS : discovers
    FINDINGS ||--o{ FINDING_STATUS_HISTORY : transitions
    USERS ||--o{ FINDING_STATUS_HISTORY : changes
    SCANS ||--o{ REPORTS : summarizes
    USERS ||--o{ AUDIT_LOGS : performs
    USERS { string id PK; string email UK; string password_hash; string role; json preferences }
    AUTH_SESSIONS { string id PK; string user_id FK; string token_hash UK; string csrf_hash; datetime expires_at }
    TARGETS { string id PK; string owner_id FK; string base_url; json scope_configuration; string authorization_status; boolean enabled }
    SCANS { string id PK; string target_id FK; string initiated_by FK; string profile; string status; datetime archived_at; integer checks_completed; integer checks_total }
    SCAN_EVENTS { string id PK; string scan_id FK; string stage; string event_type; string message; datetime created_at }
    FINDINGS { string id PK; string scan_id FK; string title; string severity; json evidence; string confidence; string verification_status; string status }
    FINDING_STATUS_HISTORY { string id PK; string finding_id FK; string changed_by FK; string previous_status; string new_status; string justification }
    REPORTS { string id PK; string scan_id FK; string format; string storage_reference; string sha256; datetime generated_at }
    AUDIT_LOGS { string id PK; string actor_id FK; string action; string resource_type; string resource_id; json details }
```

`DELETE /api/scans/{id}` is a reversible, confirmed archive from the default history, not a cascading database delete: associated findings, scan events, report files and audit events remain intact. Restore is owner-checked and audit-logged. Targets with scan history cannot be deleted; disable the target instead. A target with no scans can be deleted with explicit CSRF-authenticated confirmation and a retained audit record.
