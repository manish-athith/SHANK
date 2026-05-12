from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.models.db import get_db
from app.models.orm import User
from app.models.schemas import DetectionRequest, PredictionOut, URLPredictionRequest
from app.services.detection import DetectionEngine
from app.services.kafka_service import kafka_producer

router = APIRouter(tags=["detection"])
settings = get_settings()
detection_engine = DetectionEngine()


@router.post("/detect", response_model=PredictionOut)
@limiter.limit(settings.rate_limit_default)
async def detect(
    request: Request,
    payload: DetectionRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    event = payload.model_dump()
    event["submitted_by"] = user.email
    result = await detection_engine.analyze(db, event, persist=True)
    await db.commit()
    return result


@router.post("/predict-url", response_model=PredictionOut)
@limiter.limit(settings.rate_limit_default)
async def predict_url(
    request: Request,
    payload: URLPredictionRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    event = {"source": payload.source, "event_type": "url", "url": payload.url, "submitted_by": user.email}
    result = await detection_engine.analyze(db, event, persist=True)
    await db.commit()
    return result


@router.post("/ingest")
async def ingest_stream(
    payload: DetectionRequest,
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    event = payload.model_dump()
    event["submitted_by"] = user.email
    await kafka_producer.publish(settings.topic_raw_events, event)
    return {"status": "queued", "topic": settings.topic_raw_events}

