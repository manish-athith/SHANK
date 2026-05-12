from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SHANK"
    environment: Literal["local", "test", "prod"] = "local"
    api_prefix: str = "/api/v1"
    secret_key: str = Field(default="change-me-in-production", min_length=16)
    access_token_expire_minutes: int = 60
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    database_url: str = "postgresql+asyncpg://shank:shank@postgres:5432/shank"
    redis_url: str = "redis://redis:6379/0"
    kafka_bootstrap_servers: str = "kafka:9092"

    topic_raw_events: str = "shank.raw.events"
    topic_predictions: str = "shank.predictions"
    topic_alerts: str = "shank.alerts"
    kafka_group_id: str = "shank-detection-engine"

    model_dir: str = "ml/models"
    phishing_model_path: str = "ml/models/phishing_xgb.joblib"
    anomaly_model_path: str = "ml/models/anomaly_iforest.joblib"

    virustotal_api_key: str | None = None
    openphish_feed_url: AnyHttpUrl | str = "https://openphish.com/feed.txt"
    phishtank_feed_url: AnyHttpUrl | str = "https://data.phishtank.com/data/online-valid.csv"
    urlhaus_feed_url: AnyHttpUrl | str = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    slack_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_from: str = "alerts@shank.local"

    rate_limit_default: str = "120/minute"
    alert_throttle_seconds: int = 60
    risk_alert_threshold: int = 70

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
