from pathlib import Path

from fastapi import APIRouter
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import get_settings
from app.models.db import engine
from app.models.schemas import HealthOut

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health", response_model=HealthOut)
async def health() -> HealthOut:
    dependencies: dict[str, str] = {}

    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        dependencies["postgres"] = "ok"
    except Exception as exc:
        dependencies["postgres"] = f"error: {type(exc).__name__}"

    if settings.redis_url:
        redis: Redis | None = None
        try:
            redis = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
            await redis.ping()
            dependencies["redis"] = "ok"
        except Exception as exc:
            dependencies["redis"] = f"error: {type(exc).__name__}"
        finally:
            if redis:
                await redis.aclose()
    else:
        dependencies["redis"] = "not_configured"

    model_files = {
        "phishing": Path(settings.phishing_model_path),
        "anomaly": Path(settings.anomaly_model_path),
    }
    missing_models = [name for name, path in model_files.items() if not path.exists()]
    dependencies["models"] = f"fallback: {','.join(missing_models)}" if missing_models else "ok"
    dependencies["kafka"] = f"configured: {settings.kafka_bootstrap_servers}"

    status = "ok" if dependencies["postgres"] == "ok" and dependencies["redis"] in {"ok", "not_configured"} else "degraded"
    return HealthOut(
        status=status,
        service=settings.app_name,
        dependencies=dependencies,
    )
