"""New engines must participate in output discovery without timeline switches."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from app.tools.base import ToolAdapter
from app.tools.registry import get_adapter


@pytest.mark.parametrize(
    "tool,record,rule_id,title",
    [
        ("hayabusa", {"RuleID": "a", "RuleTitle": "Alert", "Timestamp": "2026-01-01T00:00:00Z"}, "a", "Alert"),
        ("chainsaw", {"id": "b", "name": "Alert", "Timestamp": "2026-01-01T00:00:00Z"}, "b", "Alert"),
        ("chopchopgo", {"ID": "c", "Title": "Alert", "Timestamp": "2026-01-01T00:00:00Z"}, "c", "Alert"),
        ("zircolite", {"id": "d", "title": "Alert", "matches": [{"Timestamp": "2026-01-01T00:00:00Z"}]}, "d", "Alert"),
    ],
)
def test_adapters_expose_raw_event_identity(tmp_path, tool, record, rule_id, title):
    out = tmp_path / f"log_{tool}.json"
    out.write_text(json.dumps([record] if tool in {"zircolite", "chopchopgo"} else record))
    matches = list(get_adapter(tool, {}).iter_raw_matches(out))
    assert len(matches) == 1
    assert (matches[0].rule_id, matches[0].rule_name, matches[0].timestamp) == (rule_id, title, "2026-01-01T00:00:00Z")


def test_catalog_can_load_without_application_dependencies():
    result = subprocess.run(
        [sys.executable, "-S", "-c", 'from app.tools.catalog import TOOLS; assert TOOLS["chainsaw"].version_args == ("--version",)'], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_stdout_capture_goes_to_file_not_diagnostic_memory(tmp_path):
    path = tmp_path / "matches.json"
    rc, stdout, stderr = ToolAdapter._exec([sys.executable, "-c", 'import sys; sys.stdout.write("x"*2000000); sys.stderr.write("diagnostic")'], stdout_path=path)
    assert (rc, stdout, stderr) == (0, "", "diagnostic")
    assert path.stat().st_size == 2000000


def test_stdout_capture_retains_cancellation(tmp_path):
    cancel = threading.Event()
    timer = threading.Timer(0.1, cancel.set)
    timer.start()
    try:
        rc, _, error = ToolAdapter._exec([sys.executable, "-c", "import time; time.sleep(30)"], cancel_event=cancel, stdout_path=tmp_path / "partial")
    finally:
        timer.cancel()
    assert rc == -1 and error == "cancelled"


@pytest.mark.parametrize("include_id", [True, False])
def test_markers_use_tool_and_rule_id_instead_of_shared_title(tmp_path, include_id):
    from app.intel.event_markers import MarkerAccumulator, build_index
    from app.intel.event_timeline import parse_single_output_file
    from app.intel.tactics import _build_findings_index

    def task(tool, rid, fid):
        finding = SimpleNamespace(rule_name="Same title", rule_id=rid, id=fid, severity="high", tags="[]", count=1)
        return SimpleNamespace(tool_name=tool, findings=[finding])

    meta = {}
    _build_findings_index(SimpleNamespace(task_results=[task("hayabusa", "other", 10), task("chainsaw", "wanted", 20)]), rule_meta=meta)
    out = tmp_path / "x_chainsaw.json"
    record = {"name": "Same title", "Timestamp": "2026-01-01T00:00:00Z"}
    if include_id:
        record["id"] = "wanted"
    out.write_text(json.dumps(record))
    markers = MarkerAccumulator()
    parse_single_output_file(out, {}, {}, markers=markers, rule_meta=meta)
    key = build_index(markers)["keys"][0]
    assert key[0] == "wanted"
    assert key[6] == 20


def test_doctor_reports_missing_tool_runtime_files(tmp_path, monkeypatch):
    from app import system_checks

    binary = tmp_path / "engine"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    task = {"tool": "rsigma", "tool_path": {system_checks._arch_key(): "engine"}}
    monkeypatch.setattr(system_checks, "_workflow_task_sources", lambda _: [("Windows", [task])])
    results = system_checks.check_tool_binaries(tmp_path)
    assert any(r.level == system_checks.FAIL and "mappings/windows.yml" in r.message for r in results)
