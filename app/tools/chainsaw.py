from __future__ import annotations

from pathlib import Path

from app.tools.base import ToolAdapter
from app.tools.catalog import TOOLS
from app.tools.mapping import MetadataMapping, OutputMapping, Selector, list_tags


def _document_data(event: dict):
    document = event.get("document")
    document = document if isinstance(document, dict) else {}
    return document.get("data", document)


class ChainsawAdapter(ToolAdapter):
    """
    Adapter for Chainsaw (https://github.com/WithSecureLabs/chainsaw).

    Execution mode (set in workflow YAML):

    - **tool_path** — local binary
      (``chainsaw [--num-threads N] hunt <file> --sigma <rules> …``).

    Chainsaw is **local-only** by design.  Upstream ships release binaries rather
    than a Docker image, and the vendored binaries under ``tools/chainsaw/`` are
    what every shipped workflow uses.  This adapter therefore defines no
    ``_docker_tool_args`` override, exactly like :mod:`app.tools.chopchopgo`.

    That omission is deliberate, not an oversight.  A hunt needs *three* distinct
    host paths inside the container — the Sigma rules (``--sigma``), Chainsaw's
    own rules (``-r``), and a mapping file (``--mapping``) — while the shared
    Docker runner in :class:`~app.tools.base.ToolAdapter` binds exactly one rules
    path.  Emitting ``-r``/``--mapping`` values that were never mounted would
    fail inside the container just as surely as omitting them: ``--mapping`` is a
    *required* argument whenever ``--sigma`` is used, so a partial command line
    dies on a usage error before reading a single event.  Without an override the
    base class returns a clear "does not define Docker tool arguments" error
    instead.  Wiring this up for real means teaching the base runner to bind extra
    paths — do that only if an actual Chainsaw image appears.

    **There is no official image.**  Upstream (WithSecure) ships release binaries,
    ``cargo`` and ``nix`` only; ``ghcr.io/kyverno/chainsaw`` is an unrelated project with
    the same name.  A Docker path would mean trusting an unaudited third-party image, or
    publishing our own for a binary this repo already vendors per architecture.

    If an official image appears, the mount plumbing is the easy half: add an
    ``_extra_docker_mounts() -> dict[str, str]`` hook to
    :class:`~app.tools.base.ToolAdapter` returning ``{}`` by default, merged into
    ``volumes`` *after* the literal and *before* the ``docker_options`` loop so an
    operator override still wins last, and route every path through ``_to_host_path``
    (Docker-outside-of-Docker) — which the raw ``docker_options`` seam does not do.

    Extra config keys (with defaults):

    - ``chainsaw_rules_path`` — Chainsaw built-in rules directory
      (default: ``tools/chainsaw/rules/``).
    - ``mapping_path`` — Sigma mapping file
      (default: ``tools/chainsaw/mappings/sigma-event-logs-all.yml``).
    - ``options.status`` — value for Chainsaw's ``--status`` (e.g. ``stable``,
      ``stable,experimental``).  **Unset by default**, which loads every status the
      rule files declare.  Directory selection via ``rules_path`` is the primary
      filter; this is an orthogonal one for operators who also want to exclude by the
      rule's own ``status:`` field.

    ``rules_path`` may be a **list**, in which case one ``--sigma`` flag is emitted per
    entry.  SigmaHQ splits its Windows rules across ``rules/``,
    ``rules-emerging-threats/`` and ``rules-threat-hunting/``, alongside directories that
    must *not* be loaded — ``deprecated/``, ``unsupported/``, ``rules-placeholder/`` and
    ``regression_data/`` (the last of which contains no Sigma rules at all).  Naming the
    curated directories individually is the only way to get the first set without the
    second; pointing at their shared parent gets both.
    """

    name = "chainsaw"
    output_mapping = OutputMapping(
        finding=MetadataMapping(
            rule_name=Selector((("name",), ("group",)), default="Unknown Rule", transforms=(str,)),
            rule_id=Selector((("id",),), default="", transforms=(str,)),
            severity=Selector((("level",),), default="informational", fallback="missing"),
            tags=Selector((("tags",),), default=[], transforms=(list_tags,)),
        ),
        raw_overrides={
            "rule_name": Selector((("name",), ("group",)), default="", fallback="missing"),
            "rule_id": Selector((("id",),), default="", fallback="missing"),
            "severity": Selector((("level",),), fallback="missing"),
            "tags": Selector(default=[]),
        },
        format="jsonl",
        detail_projection=_document_data,
        record_label="hit(s)",
    )

    SUPPORTED_TYPES = TOOLS["chainsaw"].supported_types

    _DEFAULT_CHAINSAW_RULES = "tools/chainsaw/rules/"
    _DEFAULT_MAPPING = "tools/chainsaw/mappings/sigma-event-logs-all.yml"

    # ── subclass hooks ───────────────────────────────────────────────────

    def _build_local_cmd(
        self,
        tool_path: Path,
        file_path: Path,
        output_file: Path,
    ) -> tuple[list[str] | None, str]:
        if err := self._check_binary_executable(tool_path):
            return None, err

        chainsaw_rules = self.config.get(
            "chainsaw_rules_path",
            self._DEFAULT_CHAINSAW_RULES,
        )
        mapping = self.config.get("mapping_path", self._DEFAULT_MAPPING)

        cmd = [str(tool_path), "--num-threads", str(self._threads)]
        cmd += ["hunt", str(file_path)]
        # `--sigma` is repeatable, which is what lets a workflow name SigmaHQ's curated
        # directories individually instead of pointing at their common parent. Verified
        # against the vendored binary: one flag loaded 3 rules where two loaded 134.
        for rules_path in self.rules_paths:
            cmd += ["--sigma", str(Path(rules_path))]
        cmd += [
            "-r",
            str(chainsaw_rules),
            "--mapping",
            str(mapping),
            "--output",
            str(output_file),
            "--jsonl",
        ]
        # Opt-in, and unset by default. Directory selection is what keeps `deprecated/` and
        # `unsupported/` out of the hunt; this is a second, orthogonal filter for operators
        # who also want to exclude by the rule's own `status:` field. Left unset the tool
        # loads every status it finds, which is the upstream default and what the curated
        # directories already assume.
        status = (self.config.get("options") or {}).get("status")
        if status:
            cmd += ["--status", str(status)]
        cmd.extend(self._extra_args)
        return cmd, ""
