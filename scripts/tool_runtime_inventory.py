#!/usr/bin/env python3
"""Pre-install workflow scalar inventory; no YAML or application dependencies.

The host scripts historically scan block-style workflow YAML with regexes.
Keep that scope: application parsing uses the full YAML loader and resolver.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.tools.catalog import TOOLS

_TOOL = re.compile(r"^(\s*)-\s+tool:\s*(.*?)\s*$")
_FIELD = re.compile(r"^(\s*)(profile|threads|docker_image|dockerfile|tool_path):\s*(.*?)\s*$")


def _scalar(value: str) -> str | None:
    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    if value[:1] in {"'", '"'}:
        quote = value[0]
        return value[1 : value.rfind(quote)]
    return None if value in {"", "null", "~"} else value


def workflow_task_scalars(text: str) -> list[dict]:
    """Read task names/profile/runner/thread scalars in block-style YAML."""
    tasks: list[dict] = []
    task = None
    key_indent = None
    for line in text.splitlines():
        match = _TOOL.match(line)
        if match:
            task = {"tool": _scalar(match[2])}
            tasks.append(task)
            key_indent = len(match[1]) + 2
        elif task is not None and (match := _FIELD.match(line)) and len(match[1]) == key_indent:
            task[match[2]] = _scalar(match[3])
    return tasks


def tool_images(project_root: Path) -> list[str]:
    """Include catalog image defaults and operator-authored inline image refs."""
    images = {spec.docker_image for spec in TOOLS.values() if spec.docker_image}
    for workflow in sorted((project_root / "workflows").glob("*.yml")):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s*docker_image:\s*(.*?)\s*$", line)
            if match and (value := _scalar(match[1])):
                images.add(value)
    return sorted(images)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", action="store_true", required=True)
    parser.add_argument("project_root", type=Path, nargs="?", default=Path.cwd())
    args = parser.parse_args()
    print("\n".join(tool_images(args.project_root)))
