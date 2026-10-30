from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.auth_schemas import Credentials
from app.core.audit import record_audit
from app.core.auth import AuthContext, clear_session_cookies, create_session, ensure_csrf_cookie, get_auth_context, reject_cross_site_browser_request, verify_csrf
from app.core.passwords import hash_password, password_needs_rehash, verify_password
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.models.entities import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", status_code=201)
def register(payload: Credentials, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    enforce_rate_limit(request, "register", 5, 3600)
    email = str(payload.email).strip().lower()
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=email, password_hash=hash_password(payload.password), role="user")
    db.add(user)
    try:
        db.flush()
        record_audit(db, actor_id=user.id, action="account.register", resource_type="user", resource_id=user.id)
        result = create_session(db, user, response)
        db.commit()
        return result
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this email already exists") from exc


@router.post("/login")
def login(payload: Credentials, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    enforce_rate_limit(request, "login", 10, 900)
    email = str(payload.email).strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or user.disabled or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    record_audit(db, actor_id=user.id, action="account.login", resource_type="user", resource_id=user.id)
    result = create_session(db, user, response)
    db.commit()
    return result


@router.get("/me")
def me(request: Request, response: Response, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    csrf = ensure_csrf_cookie(request, context, response, db)
    return {"user": {"id": context.user.id, "email": context.user.email, "role": context.user.role}, "csrfToken": csrf}


@router.post("/logout")
def logout(request: Request, response: Response, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict[str, str]:
    verify_csrf(request, context)
    record_audit(db, actor_id=context.user.id, action="account.logout", resource_type="user", resource_id=context.user.id)
    db.delete(context.session)
    db.commit()
    clear_session_cookies(response)
    return {"status": "signed_out"}
