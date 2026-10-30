from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Literal, cast

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.entities import AuthSession, User

SESSION_COOKIE = "vulnsight_session"
CSRF_COOKIE = "vulnsight_csrf"
SameSite = Literal["lax", "strict", "none"]


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: AuthSession


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _csrf_digest(value: str) -> str:
    return hmac.new(settings.session_secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _same_site() -> SameSite:
    return cast(SameSite, settings.cookie_samesite)


def _expiry_is_past(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


def reject_cross_site_browser_request(request: Request) -> None:
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        raise HTTPException(status_code=403, detail="Cross-site account requests are not permitted")


def get_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    raw_token = request.cookies.get(SESSION_COOKIE, "")
    if len(raw_token) < 40 or len(raw_token) > 256:
        raise HTTPException(status_code=401, detail="Authentication required")
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == _digest(raw_token)))
    if session is None or _expiry_is_past(session.expires_at):
        if session is not None:
            db.delete(session)
            db.commit()
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, session.user_id)
    if user is None or user.disabled:
        raise HTTPException(status_code=401, detail="Authentication required")
    return AuthContext(user=user, session=session)


def verify_csrf(request: Request, context: AuthContext) -> str:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get("X-CSRF-Token", "")
    if not cookie_token or not header_token or len(cookie_token) > 256 or len(header_token) > 256:
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    expected = _csrf_digest(cookie_token)
    if not hmac.compare_digest(expected, context.session.csrf_hash) or not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return cookie_token


def create_session(db: Session, user: User, response: Response) -> dict:
    raw_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session = AuthSession(
        user_id=user.id,
        token_hash=_digest(raw_token),
        csrf_hash=_csrf_digest(csrf_token),
        created_at=now,
        expires_at=now + timedelta(hours=settings.session_ttl_hours),
    )
    db.add(session)
    db.flush()
    max_age = settings.session_ttl_hours * 3600
    response.set_cookie(SESSION_COOKIE, raw_token, path="/", max_age=max_age, secure=settings.cookie_secure, httponly=True, samesite=_same_site())
    response.set_cookie(CSRF_COOKIE, csrf_token, path="/", max_age=max_age, secure=settings.cookie_secure, httponly=False, samesite=_same_site())
    return {"user": {"id": user.id, "email": user.email, "role": user.role}, "csrfToken": csrf_token}


def ensure_csrf_cookie(request: Request, context: AuthContext, response: Response, db: Session) -> str:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    if cookie_token and hmac.compare_digest(_csrf_digest(cookie_token), context.session.csrf_hash):
        return cookie_token
    csrf_token = secrets.token_urlsafe(32)
    context.session.csrf_hash = _csrf_digest(csrf_token)
    db.commit()
    response.set_cookie(CSRF_COOKIE, csrf_token, path="/", max_age=settings.session_ttl_hours * 3600, secure=settings.cookie_secure, httponly=False, samesite=_same_site())
    return csrf_token


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite=_same_site())
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.cookie_secure, httponly=False, samesite=_same_site())
