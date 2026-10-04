"""Pure opt-in task defaults, usable before application dependencies exist."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.tools.catalog import TOOLS

_RUNNER_SELECTORS = frozenset({"tool_path", "docker_image", "dockerfile"})


def resolve_task_config(task: dict[str, Any], tool_name: str | None = None) -> dict[str, Any]:
    """Return independent config; old tasks retain exactly their supplied fields.

    A profile supplies runner, rules and options defaults. Any explicit runner
    selector replaces the profile runner, lists replace rather than append, and
    options merge one level by key. Remove the profile marker after resolution
    so parsed tasks can be passed to the registry without applying defaults twice.
    """
    overrides = deepcopy(task)
    if "profile" not in overrides:
        return overrides
    profile_name = overrides.pop("profile")
    if not isinstance(profile_name, str) or not profile_name:
        raise ValueError("Workflow field 'profile' must be a non-empty string.")
    name = str(tool_name or overrides.get("tool", "")).lower()
    spec = TOOLS.get(name)
    if spec is None:
        raise ValueError(f"Unknown tool {name!r} for runtime profile {profile_name!r}.")
    profile = next((p for p in spec.profiles if p.name == profile_name), None)
    if profile is None:
        raise ValueError(f"Unknown profile {profile_name!r} for {name}; available: {[p.name for p in spec.profiles]}")
    defaults: dict[str, Any] = {
        "rules_path": list(profile.rules_path) if isinstance(profile.rules_path, tuple) else profile.rules_path,
    }
    if not _RUNNER_SELECTORS.intersection(overrides):
        if spec.docker_image:
            defaults["docker_image"] = spec.docker_image
        elif spec.assets:
            defaults["tool_path"] = {asset.target: f"tools/{name}/{asset.installed}" for asset in spec.assets}
    if profile.options:
        defaults["options"] = dict(profile.options)
    if "options" in overrides:
        options = overrides.pop("options")
        if not isinstance(options, dict):
            raise ValueError("Workflow profile field 'options' must be an object.")
        defaults["options"] = {**defaults.get("options", {}), **options}
    defaults.update(overrides)
    return defaults
