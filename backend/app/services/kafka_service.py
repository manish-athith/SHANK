from __future__ import annotations

import json
from typing import Any

from aiokafka import AIOKafkaProducer

from app.core.config import get_settings
from app.core.logging import logger


class KafkaProducerService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
        )
        await self.producer.start()
        logger.info("kafka_producer_started")

    async def stop(self) -> None:
        if self.producer:
            await self.producer.stop()

    async def publish(self, topic: str, event: dict[str, Any]) -> None:
        if not self.producer:
            raise RuntimeError("Kafka producer is not started")
        await self.producer.send_and_wait(topic, event)


kafka_producer = KafkaProducerService()

