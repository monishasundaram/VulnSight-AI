<p align="center">
<img src="frontend/public/favicon.svg" alt="VulnSight AI logo" width="88" />
</p> <h1 align="center">VulnSight AI</h1> <p align="center"><strong>See the risk. Fix the weakness.</strong></p>
<p align="center">A full-stack, evidence-led web security assessment workspace for authorized targets.</p> <p align="center">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white" />
  <img alt="React 19" src="https://img.shields.io/badge/React-19-149ECA?logo=react&logoColor=white" />
  <img alt="FastAPI" src="https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white" />
  <img alt="SQLite" src="https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white" />
</p>

VulnSight AI is an executable full-stack application for bounded, authorized web security checks. It combines a React dashboard with a FastAPI API, a SQLite-backed scan engine, authenticated per-user records, and downloadable reports. Dashboard metrics, scan progress, findings, history, and reports come from persisted application data—not hardcoded demo results.

> [!IMPORTANT]
**Use only against assets you own or are explicitly authorized to assess.** VulnSight enforces target scope on the server. It blocks private, loopback, link-local, multicast, reserved, and cloud-metadata destinations; limits scans to authorized hostnames and standard HTTP(S) ports 80/443; and revalidates DNS and redirect destinations. Do not bypass these protections.

## Contents

- [What it does](#what-it-does)

- [Assessment profiles](#assessment-profiles)

- [Safety and limitations](#safety-and-limitations)

- [Technology](#technology)

- [Run locally](#run-locally)
  - [Requirements](#requirements)
  - [Windows PowerShell](#windows-powershell)
  - [macOS and Linux](#macos-and-linux)
  - [Frontend development mode](#frontend-development-mode)

- [Using VulnSight](#using-vulnsight)

- [Configuration](#configuration)

- [Tests](#tests)

- [Docker](#docker)

- [API and project documentation](#api-and-project-documentation)

- [Repository layout](#repository-layout)

- [Troubleshooting](#troubleshooting)

## What it does

- **Authenticated workspace:** Argon2id password hashing, server-side sessions, CSRF validation, rate limits, and owner checks on protected records.

- **Authorized target management:** register targets, record explicit authorization and exact hostname scope, edit or disable targets, and review scan history.

- **Real background scans:** bounded workers persist scan lifecycle, completed-check events, findings, elapsed time, and cancellation state in SQLite.

- **Evidence-led checks:** inspect selected HTTP security headers, HTTPS redirect behavior, TLS certificate and handshake metadata, cookie attributes, a benign GET reflection marker, and response-configuration headers.

- **Finding triage:** filter findings, inspect expected-versus-observed evidence, follow remediation guidance, and track status changes with audit history.

- **Real reports:** preview and download owner-scoped PDF and JSON reports generated from saved scan results.

- **Data-driven dashboard:** charts, totals, activity, and recent records are derived from the signed-in user’s persisted data. New workspaces start empty.

- **Operator controls:** theme and account preferences, scan limits, report-retention settings, service health, and deployment-level finding-category severity overrides.

## Assessment profiles

| Profile | Scope |
| --- | --- |
| **Quick** | A smaller passive baseline: HTTPS/redirect behavior, TLS/certificate metadata, selected security headers, and cookie attributes. |
| **Standard** | The passive baseline plus a small predefined benign GET reflection check and selected response/configuration checks. |
| **Advanced** | The broadest available passive check set. It does not run active scans or OWASP ZAP. |

Severity labels are conservative triage categories, not CVSS scores. A deployment may optionally override labels by finding category using `SEVERITY_OVERRIDES_JSON`; the effective policy is shown in Settings. Reflection is reported as suspected evidence only—it does not prove script execution.

## Safety and limitations

VulnSight is an educational triage aid, **not** a penetration-testing suite or a guarantee that an application is secure. It does not perform active exploitation, credential attacks, arbitrary crawling, destructive payloads, data extraction, denial-of-service checks, or OWASP ZAP scans. Authenticated target application states and POST workflows are not tested.

The scanner samples a bounded number of responses and one TLS handshake. Those observations cannot describe every application route, user state, cipher, or deployment condition. Scan workers and rate limiting are process-local; this SQLite edition is intended for one application process, and unfinished scans are marked interrupted after a restart rather than resumed.

Targets must be public and explicitly authorized. Localhost, private-network hosts, custom ports, and third-party targets without permission are intentionally unsupported. The automated test suite uses an isolated synthetic loopback fixture through test-only network injection; production safeguards still reject loopback.

## Technology

- **Frontend:** React 19, TypeScript, Vite, React Router, Recharts, and Lucide.

- **Backend:** Python 3.12+, FastAPI, Pydantic, SQLAlchemy 2, and Alembic.

- **Storage:** SQLite for application records; private filesystem storage for report artifacts.

- **Security:** Argon2id password hashes, opaque hashed session tokens, CSRF checks, server-side ownership, DNS pinning, redirect revalidation, and bounded request budgets.

## Run locally

### Requirements

- Python **3.12 or newer**.

- Node.js **22.x** and npm **10.9.2**.

- A writable local filesystem for the SQLite database and generated reports.

- Docker is optional; it is not required for local development.

Open the repository root in VS Code—the directory containing `README.md`, `backend/`, `frontend/`, and `requirements.txt`—then open **Terminal → New Terminal**.

### Windows PowerShell

Run these commands from the repository root:

```
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm --prefix frontend ci
Copy-Item .env.example .env
```

Create a unique `SESSION_SECRET` in `.env` without printing it:

```
@'
from pathlib import Path
import re
import secrets

path = Path(".env")
text = path.read_text()
placeholder = "SESSION_SECRET=replace-with-a-random-secret-of-at-least-32-bytes"
if placeholder not in text:
    raise SystemExit("The example SESSION_SECRET placeholder was not found.")
text = text.replace(placeholder, "SESSION_SECRET=" + secrets.token_urlsafe(48), 1)
path.write_text(text)
'@ | .\.venv\Scripts\python.exe -
```

Apply the database migrations and build the frontend:

```
.\.venv\Scripts\alembic.exe -c alembic.ini upgrade head
npm --prefix frontend run build
```

For **plain-HTTP localhost only**, set the cookie/HSTS overrides and start FastAPI:

```
$env:COOKIE_SECURE = "false"
$env:COOKIE_SAMESITE = "lax"
$env:HSTS_ENABLED = "false"
.\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 3000
```

Leave this terminal open and visit [**http://127.0.0.1:3000/**](http://127.0.0.1:3000/). Choose **Create account**; use a valid email and a password of at least 12 characters. Stop the server with `Ctrl+C`.

### macOS and Linux

Run these commands from the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
(cd frontend && npm ci)
cp .env.example .env
```

Generate the local session secret without displaying it:

```bash
python3 - <<'PY'
from pathlib import Path
import secrets

path = Path('.env')
text = path.read_text()
placeholder = 'SESSION_SECRET=replace-with-a-random-secret-of-at-least-32-bytes'
if placeholder not in text:
    raise SystemExit('The example SESSION_SECRET placeholder was not found.')
path.write_text(text.replace(placeholder, f'SESSION_SECRET={secrets.token_urlsafe(48)}', 1))
path.chmod(0o600)
PY
```

Migrate the database and build the frontend:

```bash
.venv/bin/alembic -c alembic.ini upgrade head
(cd frontend && npm run build)
```

For **plain-HTTP localhost only**, start FastAPI with the local cookie/HSTS overrides:

```bash
COOKIE_SECURE=false COOKIE_SAMESITE=lax HSTS_ENABLED=false \
  .venv/bin/uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 3000
```

Visit [**http://127.0.0.1:3000/**](http://127.0.0.1:3000/), create an account, and keep the terminal running while you use the app. Stop with `Ctrl+C`.

> Keep `.env` private and out of source control. Do not use the local HTTP cookie overrides behind HTTPS. For public HTTPS Preview/production, keep `COOKIE_SECURE=true` and `COOKIE_SAMESITE=none`; terminate TLS at a trusted platform or reverse proxy.

### Frontend development mode

For Vite hot reload, keep FastAPI running on port `3000`, open a second terminal at the repository root, and run:

```bash
npm --prefix frontend run dev
```

Open the Vite URL it prints (normally `http://127.0.0.1:5173` ). The Vite development server proxies relative `/api` requests to FastAPI on `127.0.0.1:3000`. Use the same local-HTTP cookie settings above.

## Using VulnSight

1. Create an account and sign in.

1. Add a public target that you own or are explicitly authorized to assess. Record the exact hostname and scope; only standard HTTP(S) ports are accepted.

1. Open **New Scan**, choose a passive profile, review the target scope, and confirm authorization before launch.

1. Follow backend-reported scan progress and inspect findings, evidence, confidence, and remediation.

1. Review history and download a PDF or JSON report based on the saved results.

A target with scan history cannot be deleted. Disable it to prevent new scans while preserving its history, findings, reports, and audit records. Completed scans may be archived from the default history and restored later.

## Configuration

Copy `.env.example` to `.env` and replace its session-secret placeholder before starting the server.

| Variable | Default | Description |
| --- | --- | --- |
| `APP_ENV` | `development` | Environment label. |
| `DATABASE_URL` | `sqlite:///./data/vulnsight.db` | SQLite database location. Use a durable, writable path. |
| `SESSION_SECRET` | Replace placeholder | Unique random secret, at least 32 bytes. Never expose it in frontend code or logs. |
| `SESSION_TTL_HOURS` | `12` | Session lifetime. |
| `COOKIE_SECURE` | `true` | Keep `true` for public HTTPS; set `false` only for plain-HTTP localhost. |
| `COOKIE_SAMESITE` | `none` | Keep `none` for HTTPS Preview embedding; use `lax` for local HTTP. |
| `HSTS_ENABLED` | `true` | Enable only when the public origin uses HTTPS. |
| `MAX_TARGETS_PER_USER` | `100` | Per-user target limit. |
| `SCAN_MAX_REQUESTS` | `8` | Maximum outbound requests per scan. |
| `SCAN_MAX_REDIRECTS` | `3` | Maximum redirect hops; destinations are revalidated. |
| `SCAN_TIMEOUT_SECONDS` | `8` | Per-network-operation timeout. |
| `SCAN_MAX_DURATION_SECONDS` | `60` | Maximum scan duration. |
| `SCAN_MAX_RESPONSE_BYTES` | `524288` | Maximum response bytes processed. |
| `SCAN_MAX_CONCURRENT_JOBS` | `2` | Concurrent jobs per process. |
| `SCAN_RATE_PER_MINUTE` | `6` | Per-user scan-start limit. |
| `SEVERITY_OVERRIDES_JSON` | `{}` | Optional validated mapping from supported finding categories to severity labels; these remain triage labels, not CVSS scores. |
| `TARGET_ALLOWED_PORTS` | `80,443` | Fixed to standard HTTP(S) ports in this edition. |

The backend validates security-sensitive scan limits; clients cannot raise them through scan requests. Do not run multiple replicas against this single-process SQLite edition.

## Tests

Backend tests use disposable `/tmp` SQLite databases and report directories; they do not write to your local app database or scan third-party sites. The scanner integration tests use an isolated synthetic local HTTP/TLS fixture with test-only injected networking.

```bash
# Backend (from the repository root)
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q backend/app backend/migrations backend/tests

# Frontend (from the repository root)
(cd frontend && npm test)
(cd frontend && npm run build)
```

On Windows, use `\.venv\Scripts\python.exe` instead of `.venv/bin/python`. The suite covers authentication, authorization, SQLite persistence, target safety, DNS/redirect handling, scanner analyzers, scan progress/cancellation, findings, reports, and frontend states.

A synthetic example report is available at [`docs/sample-synthetic-report.pdf`](docs/sample-synthetic-report.pdf). It was generated from a real VulnSight scan against a synthetic local fixture; it is not a customer or third-party report.

## Docker

Docker Compose is optional. The container path builds the frontend, installs pinned Python dependencies, runs migrations, listens on port `3000`, and stores SQLite/report artifacts in a named volume.

```bash
# Prepare .env and replace SESSION_SECRET as described above.
docker compose up --build -d
docker compose ps
docker compose logs -f vulnsight
```

Open [**http://127.0.0.1:3000/**](http://127.0.0.1:3000/) only with plain-HTTP cookie settings (`COOKIE_SECURE=false`, `COOKIE_SAMESITE=lax`, `HSTS_ENABLED=false`). Stop containers without deleting data:

```bash
docker compose down
```

`docker compose down --volumes` deletes the persisted database and report volume. Use it only when you intentionally want to remove that data. For deployment, use HTTPS, a durable protected volume, and backups. Docker/Compose execution was not available in the original development sandbox, so verify the container workflow in your own Docker environment.

## API and project documentation

FastAPI provides OpenAPI JSON at `/openapi.json` and interactive API docs at `/docs`. The application health endpoint is `GET /api/health`.

- [Architecture, scan flow, and SQLite ER diagram](docs/architecture.md)

- [Project abstract, problem statement, methodology, limitations, and presentation outline](docs/project-notes.md)

- [Outcome checklist and current verification boundaries](TODO.md)

## Repository layout

```
backend/
  app/api/          Authenticated REST endpoints and request schemas
  app/core/         Sessions, CSRF, settings, audit, and rate limits
  app/models/       SQLAlchemy entities
  app/scanners/     Scope validation, safe HTTP/TLS, and analyzers
  app/workers/      Bounded background scan manager
  migrations/       Alembic schema migrations
  tests/            Backend, API, database, scanner, and report tests
frontend/
  public/            Static assets and page-route manifest
  src/pages/         Dashboard, targets, scans, findings, reports, settings, help
  src/services/      Same-origin API and authentication/session state
  src/               React application entry and shared styles

docs/                Architecture, academic project notes, synthetic report
```

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `Set SESSION_SECRET to a random value...` | Replace the placeholder in your local `.env` with the generated random secret, then restart FastAPI. |
| A workspace page says “Authentication required” | The session may be missing or expired (12 hours by default). Sign in again; protected API 401s clear stale sign-in state and return to the login page. |
| Create account reports an invalid request | Use a valid email and a password of at least 12 characters. |
| Login fails on localhost | Local HTTP requires `COOKIE_SECURE=false`, `COOKIE_SAMESITE=lax`, and `HSTS_ENABLED=false`. Clear stale localhost cookies and sign in again. |
| Login cookie is absent in HTTPS Preview | Use `COOKIE_SECURE=true` and `COOKIE_SAMESITE=none`. Browser third-party-cookie restrictions can still block embedded cookies. |
| SQLite reports a missing table/revision | From the repository root, run `.venv/bin/alembic -c alembic.ini upgrade head` (Windows: `\.venv\Scripts\alembic.exe -c alembic.ini upgrade head`). |
| Port `3000` is already in use | Stop the other process or update the server and Vite proxy configuration together. |
| Vite cannot reach the API | Ensure FastAPI is running on `127.0.0.1:3000`; Vite uses that address for its `/api` proxy. |
| Scanner rejects localhost/private/custom ports | This is intentional SSRF protection. Use the isolated synthetic fixture tests; do not whitelist loopback in production. |
| A scan is interrupted after a restart | In-process jobs are not resumed. Review persisted status/events and start a new authorized scan if appropriate. |
| Target deletion returns `409 Conflict` | Targets with scan history are retained. Disable the target instead to preserve findings, reports, and audit history. |
| PDF/JSON report generation fails | Check that the configured database/report directory is writable and has free space. |

---

**Responsible-use notice:** You are responsible for confirming authorization and scope before each assessment. VulnSight’s technical safeguards reduce risk but do not replace permission, policy review, or professional security testing.