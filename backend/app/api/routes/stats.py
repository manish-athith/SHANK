from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.models.db import get_db
from app.models.orm import Alert, PhishingEvent, User

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("")
async def get_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    event_count = await db.scalar(select(func.count()).select_from(PhishingEvent))
    alert_count = await db.scalar(select(func.count()).select_from(Alert))
    severity_rows = await db.execute(select(Alert.severity, func.count()).group_by(Alert.severity))
    domain_rows = await db.execute(
        select(PhishingEvent.domain, func.count())
        .where(PhishingEvent.domain.is_not(None))
        .group_by(PhishingEvent.domain)
        .order_by(desc(func.count()))
        .limit(10)
    )
    return {
        "events": event_count or 0,
        "alerts": alert_count or 0,
        "severity": {severity: count for severity, count in severity_rows.all()},
        "top_domains": [{"domain": domain, "count": count} for domain, count in domain_rows.all()],
    }

