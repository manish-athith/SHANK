from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.security import decode_access_token
from app.models.db import AsyncSessionLocal, get_db
from app.models.orm import Alert, User
from app.models.schemas import AlertOut
from app.services.websocket_manager import websocket_manager

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    limit: int = 50,
) -> list[Alert]:
    stmt = select(Alert).order_by(desc(Alert.created_at)).limit(min(limit, 200))
    return list((await db.execute(stmt)).scalars().all())


@router.websocket("/live")
async def live_alerts(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
    try:
        payload = decode_access_token(token)
        email = payload.get("sub")
        if not email:
            raise ValueError("Missing subject")
        async with AsyncSessionLocal() as db:
            user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
            if not user or not user.is_active:
                raise ValueError("Inactive or missing user")
    except ValueError:
        await websocket.close(code=1008)
        return
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
