from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api.dependencies import get_current_user
from app.core.security import get_password_hash
from app.main import app
from app.models.db import get_db
from app.models.orm import Alert, ModelPrediction, PhishingEvent, User


class ScalarResult:
    def __init__(self, value=None, values=None) -> None:
        self.value = value
        self.values = values or []

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.values


class FakeSession:
    def __init__(self, user: User | None = None) -> None:
        self.user = user
        self.objects = []

    async def execute(self, statement):
        text = str(statement)
        if "FROM users" in text:
            return ScalarResult(self.user)
        return ScalarResult(values=[])

    def add(self, item):
        self.objects.append(item)

    async def flush(self):
        for item in self.objects:
            if getattr(item, "id", None) is None:
                item.id = str(uuid4())
            if getattr(item, "created_at", None) is None:
                item.created_at = datetime.utcnow()
            if isinstance(item, Alert) and getattr(item, "status", None) is None:
                item.status = "open"

    async def commit(self):
        return None

    async def rollback(self):
        return None


def make_user(password: str = "CorrectHorse123!") -> User:
    return User(
        id=str(uuid4()),
        email="admin@shank.local",
        hashed_password=get_password_hash(password),
        full_name="Test Admin",
        roles=["admin", "analyst"],
        is_active=True,
        created_at=datetime.utcnow(),
    )


def override_db(session: FakeSession):
    async def dependency():
        yield session

    return dependency


@pytest.fixture(autouse=True)
def clear_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_login_success_and_failure():
    user = make_user()
    app.dependency_overrides[get_db] = override_db(FakeSession(user))

    with TestClient(app) as client:
        success = client.post(
            "/api/v1/auth/login",
            data={"username": user.email, "password": "CorrectHorse123!"},
        )
        failure = client.post(
            "/api/v1/auth/login",
            data={"username": user.email, "password": "wrong-password"},
        )

    assert success.status_code == 200
    assert success.json()["access_token"]
    assert failure.status_code == 401


def test_protected_route_rejects_missing_token():
    with TestClient(app) as client:
        response = client.get("/api/v1/stats")

    assert response.status_code == 401


def test_predict_url_returns_valid_schema():
    user = make_user()

    async def current_user():
        return user

    app.dependency_overrides[get_current_user] = current_user
    app.dependency_overrides[get_db] = override_db(FakeSession(user))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/predict-url",
            json={"url": "http://account-verify-login.example.test/session", "source": "test"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert {"event_id", "risk_score", "severity", "confidence", "phishing_probability", "anomaly_score", "features"} <= set(payload)
    assert 0 <= payload["risk_score"] <= 100
    assert payload["severity"] in {"low", "medium", "high", "critical"}


def test_websocket_rejects_missing_token():
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/api/v1/alerts/live"):
                pass

    assert exc.value.code == 1008
