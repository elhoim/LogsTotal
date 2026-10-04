"""Startup diagnostics read the same runtime paths that profile tasks execute."""

import logging

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


@pytest.mark.parametrize(
    "tasks_yaml,expected_path",
    [
        ("tasks:\n  - tool: hayabusa\n    profile: default\n", "tools/hayabusa/"),
        ("tasks:\n  - tool: hayabusa\n    tool_path: /missing/legacy-hayabusa\n", "/missing/legacy-hayabusa"),
        ("tasks:\n  - tool: hayabusa\n    profile: default\n    tool_path: /missing/override-hayabusa\n", "/missing/override-hayabusa"),
    ],
)
async def test_startup_warns_for_resolved_profile_and_legacy_paths(async_db, monkeypatch, caplog, tmp_path, tasks_yaml, expected_path):
    from app import main
    from app.models import WorkflowDef

    async_db.add(WorkflowDef(name="Missing runtime", tasks_yaml=tasks_yaml, log_types='["evtx"]'))
    await async_db.commit()
    monkeypatch.setattr(main, "async_session_maker", async_sessionmaker(async_db.bind, expire_on_commit=False))
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.WARNING, logger="app.main"):
        await main._warn_missing_tool_paths()
    assert any("Missing runtime" in record.message and expected_path in record.message and "does not exist" in record.message for record in caplog.records)
