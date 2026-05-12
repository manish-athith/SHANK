from __future__ import annotations

import asyncio
import json
from typing import Any

from aiokafka import AIOKafkaConsumer

from app.core.config import get_settings
from app.core.logging import logger
from app.services.websocket_manager import websocket_manager


class AlertFanoutService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._task: asyncio.Task[None] | None = None
        self._consumer: AIOKafkaConsumer | None = None
        self._started = asyncio.Event()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._started.clear()
        self._task = asyncio.create_task(self._run(), name="shank-alert-fanout")
        await self._started.wait()

    async def stop(self) -> None:
        if self._consumer:
            await self._consumer.stop()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        consumer = AIOKafkaConsumer(
            self.settings.topic_alerts,
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            group_id="shank-backend-alert-fanout",
            value_deserializer=lambda value: json.loads(value.decode("utf-8")),
            enable_auto_commit=True,
            auto_offset_reset="latest",
        )
        self._consumer = consumer
        try:
            await consumer.start()
            logger.info("alert_fanout_started", topic=self.settings.topic_alerts)
        except Exception as exc:
            logger.warning("alert_fanout_start_failed", error=str(exc))
            self._started.set()
            return

        self._started.set()
        try:
            async for message in consumer:
                payload = self._normalize_message(message.value)
                if payload:
                    await websocket_manager.broadcast(payload)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("alert_fanout_failed", error=str(exc))
        finally:
            logger.info("alert_fanout_stopped")

    def _normalize_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if message.get("type") == "alert" and isinstance(message.get("alert"), dict):
            return message
        alert = message.get("alert")
        if isinstance(alert, dict):
            return {"type": "alert", "alert": alert}
        if message.get("alert_created"):
            return {
                "type": "alert",
                "alert": {
                    "id": message.get("event_id") or "stream-alert",
                    "event_id": message.get("event_id"),
                    "severity": message.get("severity", "unknown"),
                    "risk_score": message.get("risk_score", 0),
                    "title": "Suspicious event detected",
                    "description": f"Event scored {message.get('risk_score', 0)}/100",
                    "status": "open",
                    "created_at": message.get("created_at"),
                },
            }
        return None


alert_fanout = AlertFanoutService()
