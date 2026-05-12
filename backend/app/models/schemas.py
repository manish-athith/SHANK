from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, HttpUrl


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str | None = None
    roles: list[str] = ["analyst"]


class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str | None
    roles: list[str]
    is_active: bool

    class Config:
        from_attributes = True


class DetectionRequest(BaseModel):
    source: str = Field(default="api", max_length=64)
    event_type: Literal["url", "email", "http", "dns", "payload"] = "url"
    url: str | None = None
    email_sender: EmailStr | None = None
    recipient: EmailStr | None = None
    subject: str | None = None
    body: str | None = None
    headers: dict[str, Any] = Field(default_factory=dict)
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)


class URLPredictionRequest(BaseModel):
    url: str
    source: str = "api"


class ThreatCheckRequest(BaseModel):
    indicator: str
    indicator_type: Literal["url", "domain", "ip", "hash"] = "url"


class PredictionOut(BaseModel):
    event_id: str | None
    risk_score: int
    severity: str
    confidence: float
    phishing_probability: float
    anomaly_score: float
    features: dict[str, Any]
    alert_created: bool = False


class AlertOut(BaseModel):
    id: str
    event_id: str | None
    severity: str
    risk_score: int
    title: str
    description: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class HealthOut(BaseModel):
    status: str
    service: str
    version: str = "1.0.0"
    dependencies: dict[str, str]

