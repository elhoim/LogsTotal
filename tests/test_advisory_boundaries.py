"""Alternate encodings and lifecycle states at the advisory boundaries."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "scripts/lib/common.sh"


def test_incomplete_threat_detection_is_visible_without_any_hits():
    from app.routers.jobs import _empty_analytics, _hydrate_analytics, templates

    data = _empty_analytics()
    data["mitre_tactics"] = {}
    data["threat_detection"]["incomplete"] = True
    data = _hydrate_analytics(data)
    body = templates.env.get_template("partials/_analytics.html").render(analytics=data, site_settings=None, job={"id": 1})
    assert "Threat detection is incomplete" in body


def _shell(tmp_path, body, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "FLEET_", "PG", "POSTGRES", "DATABASE_URL"))}
    env.update(extra, DEPLOY_ENV_FILE=str(tmp_path / "absent"))
    return subprocess.run(["bash", "-c", f'. "{COMMON}"\n{body}'], cwd=tmp_path, env=env, text=True, capture_output=True, timeout=15)


@pytest.mark.parametrize(
    "url,password",
    [
        ("postgresql://user:old@localhost/db?password=new%40pw", "new@pw"),
        ("postgresql://user@localhost/db?%70assword=first&password=last%0A", "last\n"),
        ("postgresql://user:p%2B%27%0A@localhost/db?sslmode=require", "p+'\n"),
        ("postgresql://user:@localhost/db", ""),
        ("postgresql://user@localhost/db?password=a+b&options=-c%20statement_timeout%3D5000", "a+b"),
    ],
)
def test_query_and_userinfo_passwords_leave_argv(tmp_path, url, password):
    out = _shell(tmp_path, 'resolve_pg_conn\nprintf "%s\\0%s" "$PG_URL" "$PGPASSWORD"', DATABASE_URL=url)
    assert out.returncode == 0, out.stderr
    clean, actual = out.stdout.split("\0")
    assert actual == password
    assert "password" not in clean and "%70assword" not in clean
    assert "user@" in clean
    if "sslmode" in url:
        assert "sslmode=require" in clean
    if "options" in url:
        from psycopg2.extensions import parse_dsn

        assert parse_dsn(clean)["options"] == parse_dsn(url)["options"]


@pytest.mark.parametrize("failure", ["none", "copy", "install"])
def test_env_install_is_private_atomic_and_cleans_up(tmp_path, failure):
    remote_tmp = tmp_path / "tmp with 'quotes'"
    remote_tmp.mkdir()
    dest = tmp_path / "install with 'quotes'"
    dest.mkdir()
    target = dest / ".env"
    target.write_text("old")
    target.chmod(0o644)
    src = tmp_path / "new.env"
    src.write_text("new-secret")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    if failure == "install":
        for name in ("install", "sudo"):
            exe = stubs / name
            exe.write_text("#!/bin/sh\nexit 1\n")
            exe.chmod(0o755)
    prelude = "host_copy_to() { return 1; }\n" if failure == "copy" else ""
    with target.open() as old_reader:
        out = _shell(
            tmp_path,
            prelude + 'host_install_env "$SRC" local "$DEST"',
            SRC=str(src),
            DEST=str(dest),
            TMPDIR=str(remote_tmp),
            PATH=f"{stubs}:{os.environ['PATH']}",
        )
        assert old_reader.read() == "old"
    assert (out.returncode == 0) == (failure == "none"), out.stdout + out.stderr
    assert target.read_text() == ("new-secret" if failure == "none" else "old")
    if failure == "none":
        assert target.stat().st_mode & 0o777 == 0o600
    assert list(remote_tmp.iterdir()) == []
    assert [p.name for p in dest.iterdir()] == [".env"]
