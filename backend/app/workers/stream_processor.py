from __future__ import annotations

import asyncio
import json

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.core.config import get_settings
from app.core.logging import configure_logging, logger
from app.models.db import AsyncSessionLocal, run_migrations
from app.services.detection import DetectionEngine


async def run_consumer() -> None:
    configure_logging()
    settings = get_settings()
    await run_migrations()
    detection = DetectionEngine()
    consumer = AIOKafkaConsumer(
        settings.topic_raw_events,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_group_id,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
        enable_auto_commit=False,
    )
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    await consumer.start()
    await producer.start()
    logger.info("stream_processor_started", topic=settings.topic_raw_events)
    try:
        async for message in consumer:
            async with AsyncSessionLocal() as db:
                try:
                    result = await detection.analyze(db, message.value, persist=True)
                    await db.commit()
                    await producer.send_and_wait(settings.topic_predictions, result)
                    if result["alert_created"]:
                        await producer.send_and_wait(
                            settings.topic_alerts,
                            {"type": "alert", "alert": result["alert"], "event_id": result["event_id"]},
                        )
                    await consumer.commit()
                except Exception as exc:
                    await db.rollback()
                    logger.exception("stream_event_failed", error=str(exc))
    finally:
        await consumer.stop()
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(run_consumer())
