from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import logger
from app.models.orm import Alert
from app.services.websocket_manager import websocket_manager


def serialize_alert(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "event_id": alert.event_id,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "title": alert.title,
        "description": alert.description,
        "status": alert.status,
        "created_at": alert.created_at.isoformat(),
    }


class AlertService:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def create_alert(
        self,
        db: AsyncSession,
        *,
        event_id: str | None,
        prediction_id: str | None,
        risk_score: int,
        severity: str,
        title: str,
        description: str,
        dedupe_key: str,
    ) -> Alert | None:
        throttle_after = datetime.utcnow() - timedelta(seconds=self.settings.alert_throttle_seconds)
        existing = await db.execute(
            select(Alert)
            .where(Alert.dedupe_key == dedupe_key, Alert.created_at >= throttle_after)
            .order_by(Alert.created_at.desc())
            .limit(1)
        )
        if existing.scalar_one_or_none():
            logger.info("alert_throttled", dedupe_key=dedupe_key)
            return None

        alert = Alert(
            event_id=event_id,
            prediction_id=prediction_id,
            risk_score=risk_score,
            severity=severity,
            title=title,
            description=description,
            dedupe_key=dedupe_key,
        )
        db.add(alert)
        await db.flush()
        await websocket_manager.broadcast({"type": "alert", "alert": serialize_alert(alert)})
        await self._send_slack(alert)
        return alert

    async def _send_slack(self, alert: Alert) -> None:
        if not self.settings.slack_webhook_url:
            return
        payload: dict[str, Any] = {
            "text": f"SHANK {alert.severity.upper()} alert: {alert.title} (risk {alert.risk_score})"
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(self.settings.slack_webhook_url, json=payload)
        except httpx.HTTPError as exc:
            logger.warning("slack_alert_failed", error=str(exc), alert_id=alert.id)
