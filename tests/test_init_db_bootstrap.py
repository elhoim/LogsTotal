"""init_db.py creates the .env administrator only while the instance has none.

It matched on ADMIN_EMAIL alone, so an admin who changed their address in the account menu
got a second superuser, with the .env password, on the next container start.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

STRONG = "bootstrap-Pass-9431"


@pytest.fixture()
def bootstrap_env(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL", "bootstrap@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", STRONG)


async def _superusers(db) -> list[str]:
    from app.models import User

    return sorted((await db.scalars(select(User.email).where(User.is_superuser.is_(True)))).all())


async def test_the_first_start_creates_the_admin(async_db, bootstrap_env):
    import init_db

    await init_db.main()

    assert await _superusers(async_db) == ["bootstrap@example.com"]


async def test_a_renamed_admin_is_not_recreated_on_the_next_start(async_db, admin_user, bootstrap_env):
    import init_db

    await init_db.main()

    assert await _superusers(async_db) == ["admin@test.example.com"]


async def test_recovery_still_adds_an_administrator(async_db, admin_user, bootstrap_env):
    import init_db

    await init_db.main(recovery=True)

    assert await _superusers(async_db) == ["admin@test.example.com", "bootstrap@example.com"]


async def test_recovery_never_touches_an_existing_account(async_db, admin_user, monkeypatch):
    import init_db
    from app.models import User

    before = await async_db.scalar(select(User.hashed_password).where(User.email == "admin@test.example.com"))
    monkeypatch.setenv("ADMIN_EMAIL", "admin@test.example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", STRONG)

    await init_db.main(recovery=True)

    async_db.expire_all()
    assert await async_db.scalar(select(func.count()).select_from(User)) == 1
    assert await async_db.scalar(select(User.hashed_password).where(User.email == "admin@test.example.com")) == before
