from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from aiokafka import AIOKafkaProducer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings


SAMPLE_EVENTS = [
    {
        "source": "sample-email-gateway",
        "event_type": "email",
        "url": "http://paypal-account-verify-login.secure-update.example.com/session?id=839292",
        "email_sender": "support@paypa1.example",
        "recipient": "analyst@example.com",
        "subject": "Urgent account verification required",
        "headers": {"Authentication-Results": "spf=fail dkim=fail"},
        "attachments": [{"filename": "invoice.js", "size": 18291}],
    },
    {
        "source": "sample-proxy",
        "event_type": "http",
        "url": "https://www.cloudflare.com/learning/security/",
        "headers": {},
        "payload": {"method": "GET"},
    },
]


async def main() -> None:
    settings = get_settings()
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    await producer.start()
    try:
        for event in SAMPLE_EVENTS:
            event["observed_at"] = datetime.now(timezone.utc).isoformat()
            await producer.send_and_wait(settings.topic_raw_events, event)
            print(f"sent {event['url']}")
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
