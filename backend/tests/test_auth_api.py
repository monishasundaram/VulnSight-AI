from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.auth import router as auth_router
from app.core.auth import CSRF_COOKIE, SESSION_COOKIE
from app.db.session import SessionLocal
from app.main import app
from app.models.entities import AuthSession, User


def register(client: TestClient, *, email: str | None = None) -> dict:
    response = client.post("/api/auth/register", json={"email": email or f"{uuid.uuid4().hex}@example.com", "password": "A-long-test-password-123!"})
    assert response.status_code == 201, response.text
    return response.json()


def test_register_login_me_and_logout_use_argon2_and_revocable_sessions():
    with TestClient(app) as client:
        auth = register(client)
        assert auth["user"]["role"] == "user"
        assert "password" not in auth["user"]
        assert client.cookies.get(SESSION_COOKIE)
        assert client.cookies.get(CSRF_COOKIE) == auth["csrfToken"]
        set_cookie = client.cookies
        assert set_cookie.get(SESSION_COOKIE)
        user_id = auth["user"]["id"]
        with SessionLocal() as db:
            user = db.get(User, user_id)
            assert user is not None
            assert user.password_hash.startswith("$argon2id$")
            assert not user.password_hash.endswith("A-long-test-password-123!")
            session = db.scalar(select(AuthSession).where(AuthSession.user_id == user_id))
            assert session is not None
            assert session.token_hash != client.cookies.get(SESSION_COOKIE)
        me = client.get("/api/auth/me")
        assert me.status_code == 200 and me.json()["user"]["id"] == user_id
        bad_csrf = client.post("/api/auth/logout", headers={"X-CSRF-Token": "wrong"})
        assert bad_csrf.status_code == 403
        logout = client.post("/api/auth/logout", headers={"X-CSRF-Token": auth["csrfToken"]})
        assert logout.status_code == 200
        assert client.get("/api/auth/me").status_code == 401
        login = client.post("/api/auth/login", json={"email": auth["user"]["email"], "password": "A-long-test-password-123!"})
        assert login.status_code == 200
        assert login.json()["user"]["id"] == user_id
        assert client.get("/api/auth/me").status_code == 200


def test_registration_validation_and_login_errors_do_not_echo_secrets():
    with TestClient(app) as client:
        too_short = client.post("/api/auth/register", json={"email": "bad@example.com", "password": "short"})
        assert too_short.status_code == 422
        assert "short" not in too_short.text
        missing = client.get("/api/targets")
        assert missing.status_code == 401
        invalid = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "A-long-test-password-123!"})
        assert invalid.status_code == 401
        assert invalid.json() == {"detail": "Email or password is incorrect"}
