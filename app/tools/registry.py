"""Lazy adapter lookup from the standard-library-only tool catalog."""

from importlib import import_module
from typing import Any

from app.tools.base import ToolAdapter
from app.tools.catalog import TOOLS
from app.tools.runtime import resolve_task_config


def get_adapter_class(tool_name: str) -> type[ToolAdapter]:
    spec = TOOLS.get(tool_name.lower())
    if spec is None:
        raise ValueError(f"Unknown tool: {tool_name!r}. Available: {list(TOOLS)}")
    module, name = spec.adapter.split(":")
    return getattr(import_module(module), name)


def get_adapter(tool_name: str, config: dict[str, Any]) -> ToolAdapter:
    return get_adapter_class(tool_name)(resolve_task_config(config, tool_name))
