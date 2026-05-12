from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from app.core.security import get_password_hash
from app.models.db import AsyncSessionLocal
from app.models.orm import User


async def main() -> None:
    email = os.getenv("SHANK_ADMIN_EMAIL", "admin@shank.local")
    password = os.getenv("SHANK_ADMIN_PASSWORD", "ChangeMe123!")
    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if existing:
            print(f"Admin user already exists: {email}")
            return
        db.add(
            User(
                id=str(uuid4()),
                email=email,
                hashed_password=get_password_hash(password),
                full_name="SHANK Admin",
                roles=["admin", "analyst"],
                is_active=True,
            )
        )
        await db.commit()
        print(f"Created admin user: {email}")


if __name__ == "__main__":
    asyncio.run(main())
