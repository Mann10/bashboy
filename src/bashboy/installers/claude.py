"""Claude Code installer: merge a PreToolUse hook into ``settings.json``.

The merge is idempotent and non-clobbering: unrelated keys and unrelated hook
events survive, and an existing BashBoy handler is updated in place rather than
duplicated. The file is backed up before the first write and replaced
atomically.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from ..config import ConfigError, load_config
from . import atomic_write_text

MATCHER = "Bash|PowerShell"
STATUS_MESSAGE = "BashBoy: checking command"


def default_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def _resolve_path(settings_path: Path | str | None) -> Path:
    return Path(settings_path) if settings_path else default_settings_path()


def _load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"{path}: not valid JSON ({exc}); refusing to modify it"
        ) from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a JSON object; refusing to modify it")
    return data


def build_handler(timeout_s: int = 15, from_spec: str | None = None) -> dict:
    args = ["bashboy", "check", "--claude-hook"]
    if from_spec:
        args = ["--from", from_spec, *args]
    return {
        "type": "command",
        "command": "uvx",
        "args": args,
        "timeout": int(timeout_s),
        "statusMessage": STATUS_MESSAGE,
    }


def _is_bashboy_handler(candidate: object) -> bool:
    if not isinstance(candidate, dict):
        return False
    args = candidate.get("args")
    return isinstance(args, list) and "bashboy" in args and "--claude-hook" in args


def merge_handler(settings: dict, handler: dict) -> dict:
    """Return ``settings`` with ``handler`` present exactly once under PreToolUse."""
    hooks = settings.get("hooks")
    if hooks is None:
        hooks = {}
        settings["hooks"] = hooks
    elif not isinstance(hooks, dict):
        raise ConfigError("settings 'hooks' must be a JSON object")

    entries = hooks.get("PreToolUse")
    if entries is None:
        entries = []
        hooks["PreToolUse"] = entries
    elif not isinstance(entries, list):
        raise ConfigError("settings 'hooks.PreToolUse' must be a JSON array")

    target = None
    for entry in entries:
        if isinstance(entry, dict) and entry.get("matcher") == MATCHER:
            target = entry
            break

    if target is None:
        entries.append({"matcher": MATCHER, "hooks": [handler]})
        return settings

    existing = target.get("hooks")
    if not isinstance(existing, list):
        existing = []
        target["hooks"] = existing

    for index, candidate in enumerate(existing):
        if _is_bashboy_handler(candidate):
            updated = dict(candidate)
            updated.update(handler)
            existing[index] = updated
            return settings

    existing.append(handler)
    return settings


def install_claude(
    settings_path: Path | str | None = None,
    *,
    from_spec: str | None = None,
    dry_run: bool = False,
) -> dict:
    """Merge the BashBoy hook and (unless ``dry_run``) write the settings file."""
    path = _resolve_path(settings_path)
    cfg = load_config()
    settings = _load_settings(path)
    merged = merge_handler(settings, build_handler(cfg.claude.timeout_s, from_spec))

    if dry_run:
        return merged

    if path.exists():
        backup = Path(str(path) + ".bak")
        try:
            shutil.copyfile(path, backup)
        except OSError as exc:
            raise ConfigError(f"cannot back up {path}: {exc}") from exc
        print(f"bashboy: backup at {backup}", file=sys.stderr)

    atomic_write_text(path, json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
    return merged
