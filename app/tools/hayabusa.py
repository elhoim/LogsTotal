from __future__ import annotations

import logging
from pathlib import Path

from app.tools.base import ToolAdapter
from app.tools.catalog import TOOLS
from app.tools.mapping import MetadataMapping, OutputMapping, Selector, csv_tags

_log = logging.getLogger(__name__)

# Hayabusa's own `-m/--min-level` vocabulary, which happens to coincide with LogsTotal's
# severities but is not the same list — it names the levels of the *rules loaded*, not of
# the findings produced. `MIN_LEVEL_FLAGS` is the dedupe set: `_core_args` appends
# `extra_args` verbatim, so a workflow that already passes the flag there must not get a
# second copy from `options` (the `-AU`/`-S`/`-j` rule in zircolite.py).
MIN_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
MIN_LEVEL_FLAGS = ("-m", "--min-level")


class HayabusaAdapter(ToolAdapter):
    """
    Adapter for Hayabusa (https://github.com/Yamato-Security/hayabusa).

    Execution modes (set in workflow YAML):

    - **tool_path** — local binary
      (``hayabusa dfir-timeline --output-type jsonl -f <file> …``). Requires Hayabusa 4.
      This is what every shipped
      workflow uses; the binaries are vendored under ``tools/hayabusa/``.
    - **docker_image** / **dockerfile** — run inside a Docker container.  Upstream
      publishes no official image, so this means one you build yourself; it works
      because :meth:`_core_args` is shared with the local path and takes its log,
      output and rules as *refs*, so the Docker override simply passes
      container-side paths.  Contrast :mod:`app.tools.chainsaw`, which needs more
      paths mounted than the base runner binds and so stays local-only.

    Extra config (nested under ``options``):

    - ``min_level`` — the lowest rule level to load, one of :data:`MIN_LEVELS`. Omit it to
      take Hayabusa's own default (``informational``, i.e. every rule).
    """

    name = "hayabusa"
    output_mapping = OutputMapping(
        finding=MetadataMapping(
            rule_name=Selector((("RuleTitle",), ("Channel",)), default="Unknown Rule", transforms=(str,)),
            rule_id=Selector((("RuleID",), ("RuleFile",)), default="", transforms=(str,)),
            severity=Selector((("Level",),), default="informational", fallback="missing"),
            tags=Selector((("MitreTags",),), default="", fallback="missing", transforms=(csv_tags,)),
        ),
        raw_overrides={
            "rule_name": Selector((("RuleTitle",),), default="", fallback="missing"),
            "rule_id": Selector((("RuleID",),), default="", fallback="missing"),
            "severity": Selector((("Level",),), fallback="missing"),
            "tags": Selector(default=[]),
        },
        format="jsonl",
        detail_projection=lambda event: {key: event.get(key) for key in ("Timestamp", "Computer", "EventID", "Details")},
    )

    SUPPORTED_TYPES = TOOLS["hayabusa"].supported_types

    # ── subclass hooks ───────────────────────────────────────────────────

    def _core_args(
        self,
        log_ref: str,
        output_ref: str,
        rules_ref: str,
    ) -> list[str]:
        """Hayabusa CLI flags shared between local and Docker modes."""
        args = [
            "dfir-timeline",
            "-f",
            log_ref,
            "-o",
            output_ref,
            "-r",
            rules_ref,
            "-q",
            "--no-wizard",
            "--output-type",
            "jsonl",
            "-p",
            "super-verbose",
            "-K",
        ]
        # In v4, -t selects the output format. Only the long flag sets threads.
        args += ["--threads", str(self._threads)]
        args += self._min_level_args()
        args.extend(self._extra_args)
        return args

    def _min_level_args(self) -> list[str]:
        """``options.min_level`` → ``-m <level>``, or nothing.

        An unrecognised level is dropped with a warning rather than passed through:
        Hayabusa exits non-zero on a bad ``-m``, so a typo in an optional knob would fail
        the whole task instead of the run it was meant to narrow.
        """
        options = self.config.get("options") or {}
        level = str(options.get("min_level") or "").strip().lower()
        if not level:
            return []
        if any(flag in self._extra_args for flag in MIN_LEVEL_FLAGS):
            return []
        if level not in MIN_LEVELS:
            _log.warning("hayabusa: ignoring unknown min_level %r (expected one of %s)", level, ", ".join(sorted(MIN_LEVELS)))
            return []
        return ["-m", level]

    def _build_local_cmd(
        self,
        tool_path: Path,
        file_path: Path,
        output_file: Path,
    ) -> tuple[list[str] | None, str]:
        if err := self._check_binary_executable(tool_path):
            return None, err

        rules_path = Path(self.rules_path)
        cmd = [
            str(tool_path),
            *self._core_args(str(file_path), str(output_file), str(rules_path)),
        ]
        return cmd, ""

    def _docker_tool_args(
        self,
        container_log: str,
        container_rules: str,
        container_out: str,
    ) -> list[str]:
        return self._core_args(container_log, container_out, container_rules)
