from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router, scan_manager
from app.api.settings import router as settings_router
from app.api.targets import router as targets_router
from app.core.config import settings, validate_runtime_settings
from app.db.session import engine, init_db


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    validate_runtime_settings()
    init_db()
    scan_manager.recover_interrupted_scans()
    yield


app = FastAPI(
    title="VulnSight AI API",
    version="1.0.0",
    description="Authorized, evidence-led web security assessment service.",
    lifespan=lifespan,
)
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(settings_router)
app.include_router(targets_router)
app.include_router(scans_router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    # Pydantic's default may echo password/body input; return a static message only.
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


@app.exception_handler(Exception)
async def internal_error_handler(_: Request, __: Exception) -> JSONResponse:
    # Do not serialize exception text, stack traces, credentials, cookies or submitted target data.
    return JSONResponse(status_code=500, content={"detail": "Request could not be completed"})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'"
    )
    if settings.hsts_enabled:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health", tags=["health"])
def health() -> dict[str, str]:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok", "database": "sqlite", "version": app.version}


STATIC_DIR = Path(__file__).parent / "static"
PUBLIC_DIR = (Path(__file__).resolve().parents[2] / "frontend" / "public").resolve()
if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets", check_dir=False), name="assets")


@app.get("/manus-routes.json", include_in_schema=False)
def routes_manifest():
    built = STATIC_DIR / "manus-routes.json"
    source = PUBLIC_DIR / "manus-routes.json"
    path = built if built.is_file() else source
    if not path.is_file():
        return JSONResponse({"detail": "Route manifest is not built."}, status_code=404)
    return FileResponse(path, media_type="application/json")


@app.get("/{path:path}", include_in_schema=False)
def spa_fallback(path: str):
    if path == "api" or path.startswith("api/"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    for root in (STATIC_DIR.resolve(), PUBLIC_DIR):
        candidate = (root / path).resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return FileResponse(candidate)
    index = STATIC_DIR / "index.html"
    if index.is_file():
        return FileResponse(index)
    return JSONResponse({"detail": "Frontend assets are not built. Run `npm run build` in frontend/."}, status_code=503)
