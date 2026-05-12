from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.models.db import get_db
from app.models.orm import User
from app.models.schemas import ThreatCheckRequest
from app.services.threat_intel import ThreatIntelService

router = APIRouter(tags=["threat-intelligence"])
threat_intel = ThreatIntelService()


@router.post("/threat-check")
async def threat_check(
    payload: ThreatCheckRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return await threat_intel.lookup(db, payload.indicator, payload.indicator_type)

