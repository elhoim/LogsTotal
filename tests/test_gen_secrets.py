"""Tests for scripts/gen_secrets.py — secret generation and .env writing."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "gen_secrets.py"


@pytest.fixture()
def gen_secrets():
    spec = importlib.util.spec_from_file_location("gen_secrets", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", True),
        ("  ", True),
        ("change-me-in-production", True),
        ("change-me-to-a-long-random-string-in-production", True),
        ("change-me-anything", True),  # prefix rule
        ("changeme123", True),  # shipped ADMIN_PASSWORD default
        ("set-a-strong-password", True),
        ('"change-me-in-production"', True),  # quoted placeholder
        ("a-real-secret-value", False),
        ("hunter2hunter2hunter2", False),
    ],
)
def test_is_placeholder(gen_secrets, value, expected):
    assert gen_secrets._is_placeholder(value) is expected


def test_placeholders_stay_superset_of_config(gen_secrets):
    """gen_secrets is stdlib-only (quickstart runs it without a venv), so its
    placeholder list is a literal — pin it against app.config so they can't drift."""
    from app.config import settings

    config_placeholders = (
        set(settings._PLACEHOLDER_S3_ACCESS_KEYS) | set(settings._PLACEHOLDER_S3_SECRET_KEYS) | {"change-me-in-production", "change-me-to-a-long-random-string-in-production"}
    )
    missing = config_placeholders - gen_secrets.PLACEHOLDER_VALUES
    assert not missing, f"scripts/gen_secrets.py PLACEHOLDER_VALUES is missing config placeholders: {missing}"


def test_generate_covers_admin_password(gen_secrets):
    values = gen_secrets.generate()
    assert "ADMIN_PASSWORD" in values
    assert len(values["ADMIN_PASSWORD"]) >= 12  # init_db warns under 12 chars
    assert "SECRET_KEY" in values
    assert len(values["SECRET_KEY"]) >= 32


def test_write_env_fills_placeholders_keeps_real_values(gen_secrets, tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text(
        "SECRET_KEY=change-me-in-production\nADMIN_PASSWORD=changeme123\nREDIS_PASSWORD=\nPOSTGRES_PASSWORD=my-real-password-123\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen_secrets, "PROJECT_ROOT", tmp_path)

    values = gen_secrets.generate()
    rc = gen_secrets.write_env(values, force=False)
    assert rc == 0

    text = env.read_text(encoding="utf-8")
    assert f"SECRET_KEY={values['SECRET_KEY']}" in text
    assert f"ADMIN_PASSWORD={values['ADMIN_PASSWORD']}" in text
    assert f"REDIS_PASSWORD={values['REDIS_PASSWORD']}" in text
    assert "POSTGRES_PASSWORD=my-real-password-123" in text  # never clobbered
    # Absent keys get appended so they take effect
    assert f"S3_ACCESS_KEY={values['S3_ACCESS_KEY']}" in text
    # Newly written admin password is echoed once, highlighted
    out = capsys.readouterr().out
    assert "ADMIN LOGIN" in out
    assert values["ADMIN_PASSWORD"] in out


def test_write_env_rerun_is_noop_for_real_values(gen_secrets, tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text("SECRET_KEY=change-me-in-production\n", encoding="utf-8")
    monkeypatch.setattr(gen_secrets, "PROJECT_ROOT", tmp_path)

    first = gen_secrets.generate()
    gen_secrets.write_env(first, force=False)
    text_after_first = env.read_text(encoding="utf-8")
    capsys.readouterr()

    second = gen_secrets.generate()
    gen_secrets.write_env(second, force=False)
    assert env.read_text(encoding="utf-8") == text_after_first  # idempotent
    out = capsys.readouterr().out
    assert "ADMIN LOGIN" not in out  # password not re-printed when unchanged


def test_write_env_missing_env_file_errors(gen_secrets, tmp_path, monkeypatch):
    monkeypatch.setattr(gen_secrets, "PROJECT_ROOT", tmp_path)
    assert gen_secrets.write_env(gen_secrets.generate(), force=False) == 1


# ── .env holds every secret: it must not be readable by other local users ────


@pytest.fixture()
def umask_022():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def test_write_env_leaves_a_world_readable_env_owner_only(gen_secrets, tmp_path, monkeypatch, umask_022):
    """`cp .env.example .env` makes a 0644 file under the usual umask; the secrets written
    into it must not inherit that mode."""
    env = tmp_path / ".env"
    env.write_text("SECRET_KEY=change-me-in-production\nADMIN_PASSWORD=changeme123\n", encoding="utf-8")
    env.chmod(0o644)
    monkeypatch.setattr(gen_secrets, "PROJECT_ROOT", tmp_path)

    assert gen_secrets.write_env(gen_secrets.generate(), force=False) == 0
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


@pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None, reason="bash/python3 not available")
def test_env_bootstrap_creates_an_owner_only_env(tmp_path, umask_022):
    """The real `task setup` path: env-bootstrap.sh copies the template, then fills it."""
    repo = SCRIPT.parent.parent
    shutil.copytree(repo / "scripts", tmp_path / "scripts")
    shutil.copy(repo / ".env.example", tmp_path / ".env.example")
    result = subprocess.run(["bash", "scripts/env-bootstrap.sh"], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr

    assert "ADMIN LOGIN" in result.stdout  # the secrets really were written
    assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600


def test_private_replacement_does_not_feed_open_readers(gen_secrets, tmp_path):
    path = tmp_path / "env"
    path.write_text("old")
    path.chmod(0o644)
    link = tmp_path / "hardlink"
    os.link(path, link)
    with path.open() as reader:
        gen_secrets.write_private(path, "new-secret")
        assert reader.read() == "old"
    assert link.read_text() == "old"
    assert path.read_text() == "new-secret"
    assert path.stat().st_mode & 0o777 == 0o600


def test_private_replacement_refuses_symlinks_and_preserves_on_error(gen_secrets, tmp_path, monkeypatch):
    path = tmp_path / "env"
    path.write_text("original")
    link = tmp_path / "symlink"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        gen_secrets.write_private(link, "new-secret")
    assert path.read_text() == "original"

    def fail(*args):
        raise OSError("injected failure")

    monkeypatch.setattr(gen_secrets.os, "replace", fail)
    with pytest.raises(OSError):
        gen_secrets.write_private(path, "new-secret")
    assert path.read_text() == "original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["env", "symlink"]
