"""Shared mappings keep reported detections separate from evidence samples."""

import importlib.util
import json
import sys
from dataclasses import replace

import pytest

from app.tools.base import ToolAdapter


def declared_adapter(*, format="json", strict=False):
    api = mapping_api()

    class DeclaredAdapter(ToolAdapter):
        name = "declared"
        output_mapping = api.OutputMapping(
            finding=api.MetadataMapping(rule_name=api.Selector((("title",),), default="Unknown Rule")),
            format=format,
            strict=strict,
        )

    return DeclaredAdapter


def mapping_api():
    assert importlib.util.find_spec("app.tools.mapping") is not None, "shared output decoder is missing"
    from app.tools import mapping

    return mapping


def test_selector_uses_explicit_paths_ordered_fallbacks_and_transforms():
    api = mapping_api()
    selector = api.Selector((("nested", "title"), ("literal.dot",)), default="unknown", transforms=(str, str.upper))
    assert selector.read({"nested": {"title": ""}, "literal.dot": "fallback"}) == "FALLBACK"
    assert selector.read({"nested.title": "wrong"}) == "UNKNOWN"
    present = api.Selector((("value",), ("fallback",)), default="missing", fallback="missing")
    assert present.read({"value": None, "fallback": "wrong"}) is None


def test_new_mapping_normalizes_and_reads_raw_matches_without_vendor_branches(tmp_path):
    api = mapping_api()

    class ExampleAdapter(ToolAdapter):
        name = "example"
        output_mapping = api.OutputMapping(
            finding=api.MetadataMapping(
                rule_name=api.Selector((("rule", "title"),), default="Unknown Rule"),
                rule_id=api.Selector((("rule", "id"),), default=""),
                severity=api.Selector((("rule", "level"),), default=None),
            ),
            events=api.Selector((("evidence",),), default=[]),
            reported_count=api.Selector((("total",),), default=None, fallback="missing"),
            grouping="blocks",
        )

        def _output_filename(self, file_path):
            return file_path.stem + ".json"

    records = [{"rule": {"title": "Alert", "id": "r", "level": "high"}, "total": 7, "evidence": []}]
    findings = ExampleAdapter({}).normalize(records)
    assert [(f.rule_name, f.severity, f.count, f.details) for f in findings] == [("Alert", "high", 7, [])]
    records[0]["evidence"] = [{"Timestamp": "2026-01-01T00:00:00Z", "value": 42}]
    path = tmp_path / "output.json"
    path.write_text(json.dumps(records))
    matches = list(ExampleAdapter.iter_raw_matches(path))
    assert len(matches) == 1
    assert (matches[0].rule_name, matches[0].rule_id, matches[0].severity) == ("Alert", "r", "high")
    assert matches[0].event == {"Timestamp": "2026-01-01T00:00:00Z", "value": 42}


def test_decoder_retains_count_when_no_events_exist():
    api = mapping_api()
    mapping = api.OutputMapping(
        finding=api.MetadataMapping(rule_name=api.Selector((("name",),), default="Unknown Rule")),
        events=api.Selector((("events",),), default=[]),
        reported_count=api.Selector((("count",),), default=None),
        grouping="blocks",
    )
    decoded = list(api.decode_records([{"name": "Empty evidence", "count": 12}], mapping))
    assert len(decoded) == 1
    assert decoded[0].reported_count == 12
    assert decoded[0].events == []


def test_shared_jsonl_reader_streams_and_preserves_strict_errors(tmp_path):
    api = mapping_api()
    path = tmp_path / "output.jsonl"
    path.write_text('{"name":"first"}\ninvalid\n{"name":"last"}\n')
    assert list(api.file_records(path, format="jsonl")) == [{"name": "first"}, {"name": "last"}]
    records = api.file_records(path, format="jsonl", strict=True)
    assert next(records) == {"name": "first"}
    with pytest.raises(ValueError):
        next(records)


def test_rsigma_retains_empty_event_objects():
    from app.tools.rsigma import RsigmaAdapter

    record = {"rule_title": "Alert", "event": {}}
    assert RsigmaAdapter._match(record).event == {}
    finding = RsigmaAdapter({}).normalize([record])[0]
    assert (finding.rule_name, finding.count, finding.details) == ("Alert", 1, [{}])


@pytest.mark.parametrize("titles", [["one"], ["one", "two"]])
def test_declared_jsonl_format_controls_execution_parsing(tmp_path, titles):
    adapter_cls = declared_adapter(format="jsonl")
    output = tmp_path / "output.jsonl"
    output.write_text("".join(json.dumps({"title": title}) + "\n" for title in titles))
    result = adapter_cls({})._execute_and_parse([sys.executable, "-c", "pass"], output)
    assert result.success, result.error
    assert [(finding.rule_name, finding.count) for finding in result.findings] == [(title, 1) for title in titles]
    assert [match.rule_name for match in adapter_cls.iter_raw_matches(output)] == titles


@pytest.mark.parametrize("records", [{}, 42, None, [{"title": "one"}, 42]])
def test_strict_json_execution_and_readers_reject_invalid_output(tmp_path, records):
    adapter_cls = declared_adapter(strict=True)
    output = tmp_path / "output.json"
    output.write_text(json.dumps(records))
    result = adapter_cls({})._execute_and_parse([sys.executable, "-c", "pass"], output)
    assert not result.success, "strict output must not become a clean or partial successful scan"
    with pytest.raises(ValueError):
        list(adapter_cls.iter_raw_matches(output))
    with pytest.raises(ValueError):
        list(mapping_api().file_records(output, format="json", strict=True))
    with pytest.raises(ValueError):
        adapter_cls({}).normalize(records)


def test_strict_json_accepts_valid_output(tmp_path):
    adapter_cls = declared_adapter(strict=True)
    output = tmp_path / "output.json"
    output.write_text('[{"title":"one"}]')
    result = adapter_cls({})._execute_and_parse([sys.executable, "-c", "pass"], output)
    assert result.success, result.error
    assert result.findings[0].rule_name == "one"


def test_catalog_capabilities_gate_declared_adapter_before_execution(monkeypatch, tmp_path):
    from app.tools.catalog import TOOLS

    adapter_cls = declared_adapter()
    monkeypatch.setitem(TOOLS, "declared", replace(TOOLS["hayabusa"], name="declared", supported_types=frozenset({"supported"})))

    def unexpected_execution(*args):
        pytest.fail("unsupported catalog log type reached CLI construction")

    monkeypatch.setattr(adapter_cls, "_build_local_cmd", unexpected_execution)
    output_dir = tmp_path / "output"
    result = adapter_cls({"tool_path": "/fake"}).run(tmp_path / "input", output_dir, log_type="unsupported")
    assert not result.success and result.error == "not supported"
    assert not output_dir.exists()
