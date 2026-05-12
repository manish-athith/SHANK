from __future__ import annotations

import asyncio
import csv
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy.dialects.postgresql import insert

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.db import AsyncSessionLocal
from app.models.orm import ThreatFeed


def indicators_from_files(downloaded_dir: Path) -> list[dict]:
    records: list[dict] = []
    openphish = downloaded_dir / "openphish.txt"
    if openphish.exists():
        records.extend(
            {
                "id": str(uuid4()),
                "provider": "openphish",
                "indicator": line.strip(),
                "indicator_type": "url",
                "metadata_json": {},
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
            }
            for line in openphish.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    urlhaus = downloaded_dir / "urlhaus.csv"
    if urlhaus.exists():
        for line in urlhaus.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            try:
                parts = next(csv.reader([line]))
            except csv.Error as exc:
                print(f"Warning: skipped malformed URLHaus row: {exc}")
                continue
            if len(parts) > 2:
                records.append(
                    {
                        "id": str(uuid4()),
                        "provider": "urlhaus",
                        "indicator": parts[2],
                        "indicator_type": "url",
                        "metadata_json": {"threat": parts[4] if len(parts) > 4 else "malware"},
                        "first_seen": datetime.utcnow(),
                        "last_seen": datetime.utcnow(),
                    }
                )

    phishtank = downloaded_dir / "phishtank.csv"
    if phishtank.exists():
        with phishtank.open(newline="", encoding="utf-8", errors="ignore") as handle:
            for row in csv.DictReader(handle):
                url = row.get("url")
                if not url:
                    continue
                records.append(
                    {
                        "id": str(uuid4()),
                        "provider": "phishtank",
                        "indicator": url,
                        "indicator_type": "url",
                        "metadata_json": {"phish_id": row.get("phish_id")},
                        "first_seen": datetime.utcnow(),
                        "last_seen": datetime.utcnow(),
                    }
                )
    return records


async def main() -> None:
    records = indicators_from_files(Path("datasets/downloaded"))
    if not records:
        print("No downloaded threat-feed records found. Run scripts/download_feeds.py first.")
        return
    async with AsyncSessionLocal() as db:
        stmt = insert(ThreatFeed).values(records).on_conflict_do_nothing(
            index_elements=["provider", "indicator"]
        )
        await db.execute(stmt)
        await db.commit()
    print(f"Ingested {len(records)} threat-feed indicators")


if __name__ == "__main__":
    asyncio.run(main())
