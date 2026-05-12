from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import logger
from app.models.orm import ThreatFeed
from app.services.feature_extraction import extract_domain


class ThreatIntelService:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def local_lookup(self, db: AsyncSession, indicator: str) -> dict[str, Any]:
        domain = extract_domain(indicator) or indicator.lower()
        stmt = select(ThreatFeed).where(
            (ThreatFeed.indicator == indicator) | (ThreatFeed.indicator == domain)
        ).limit(10)
        rows = (await db.execute(stmt)).scalars().all()
        return {
            "hit": bool(rows),
            "matches": [
                {
                    "provider": row.provider,
                    "indicator": row.indicator,
                    "indicator_type": row.indicator_type,
                    "metadata": row.metadata_json,
                }
                for row in rows
            ],
        }

    async def virustotal_lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if not self.settings.virustotal_api_key:
            return {"enabled": False, "hit": False, "reason": "VIRUSTOTAL_API_KEY not configured"}

        headers = {"x-apikey": self.settings.virustotal_api_key}
        endpoint_map = {
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
            "url": "https://www.virustotal.com/api/v3/urls",
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                if indicator_type == "url":
                    submit = await client.post(endpoint_map["url"], headers=headers, data={"url": indicator})
                    submit.raise_for_status()
                    analysis_id = submit.json()["data"]["id"]
                    response = await client.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                    )
                else:
                    response = await client.get(endpoint_map[indicator_type], headers=headers)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            logger.warning("virustotal_lookup_failed", error=str(exc), indicator=indicator)
            return {"enabled": True, "hit": False, "error": str(exc)}

        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        return {"enabled": True, "hit": malicious + suspicious > 0, "stats": stats}

    async def lookup(self, db: AsyncSession, indicator: str, indicator_type: str = "url") -> dict[str, Any]:
        local = await self.local_lookup(db, indicator)
        vt = await self.virustotal_lookup(indicator, indicator_type)
        return {"hit": bool(local["hit"] or vt.get("hit")), "local": local, "virustotal": vt}

