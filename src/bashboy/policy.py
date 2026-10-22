"""Layered command policy: org, user, project, and built-ins.

Policy files are TOML. Precedence, highest first:

1. ``BASHBOY_POLICY`` -- one explicit file; replaces discovery (tests, CI).
2. **org** -- ``BASHBOY_POLICY_ORG`` or the platform system path.
3. **user** -- ``BASHBOY_POLICY_USER`` or ``~/.bashboy/policy.toml``.
4. **project** -- ``BASHBOY_POLICY_PROJECT`` or the nearest
   ``.bashboy/policy.toml`` walking up from the working directory.

Built-in rules (:mod:`bashboy.rules`) are enforced after the custom sources.

Project policies are **tighten-only**: an ``allow`` rule in a checked-in file is
ignored, so cloning an untrusted repository cannot loosen the gate. An org
policy with ``immutable = true`` ignores ``allow`` rules from user and project
files too; org ``deny`` rules always win.

First matching rule wins. Matching is applied to the raw command and to every
executable fragment (the same split as the built-in denylist), so
``ls; rm -rf /`` is caught by a rule for ``rm``.

This module is stdlib-only and does no network I/O.
"""

from __future__ import annotations

import fnmatch
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .rules import segments

MAX_PATTERN_LENGTH = 512
MAX_COMMAND_LENGTH = 64 * 1024
ACTIONS = ("deny", "allow")
_RULE_KEYS = frozenset({"id", "action", "reason", "match", "contains", "cwd"})


class PolicyError(Exception):
    """Raised when a policy file cannot be read, parsed, or validated."""


@dataclass(frozen=True)
class PolicyFlags:
    """Org-level switches. Only org (or explicit) files may set these."""

    immutable: bool = False
    disable_escape_hatch: bool = False
    require_key: bool = False


@dataclass(frozen=True)
class PolicyRule:
    id: str
    action: str
    reason: str
    source: str
    path: Path
    regex: re.Pattern[str] | None = None
    contains: str | None = None
    cwd: str | None = None
    ignored: str | None = None


@dataclass(frozen=True)
class PolicySet:
    rules: tuple[PolicyRule, ...]
    flags: PolicyFlags
    sources: tuple[tuple[str, Path, bool], ...]


@dataclass(frozen=True)
class PolicyHit:
    decision: str
    rule_id: str
    reason: str
    source: str


def org_policy_path() -> Path:
    override = os.environ.get("BASHBOY_POLICY_ORG")
    if override and override.strip():
        return Path(override.strip()).expanduser()
    if os.name == "nt":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "BashBoy" / "policy.toml"
    return Path("/etc/bashboy/policy.toml")


def user_policy_path() -> Path:
    override = os.environ.get("BASHBOY_POLICY_USER")
    if override and override.strip():
        return Path(override.strip()).expanduser()
    return Path.home() / ".bashboy" / "policy.toml"


def project_policy_path(cwd: str | None = None) -> Path:
    override = os.environ.get("BASHBOY_POLICY_PROJECT")
    if override and override.strip():
        return Path(override.strip()).expanduser()
    start = Path(cwd or os.getcwd()).resolve()
    for parent in (start, *start.parents):
        candidate = parent / ".bashboy" / "policy.toml"
        if candidate.is_file():
            return candidate
    return start / ".bashboy" / "policy.toml"


def policy_paths(cwd: str | None = None) -> tuple[tuple[str, Path], ...]:
    """Return ``(source, path)`` pairs in precedence order."""
    explicit = os.environ.get("BASHBOY_POLICY")
    if explicit and explicit.strip():
        return (("explicit", Path(explicit.strip()).expanduser()),)
    return (
        ("org", org_policy_path()),
        ("user", user_policy_path()),
        ("project", project_policy_path(cwd)),
    )


def _as_bool(table: dict, key: str, where: Path) -> bool:
    value = table.get(key, False)
    if not isinstance(value, bool):
        raise PolicyError(f"{where}: policy.{key} must be true or false")
    return value


def _parse_rule(
    item: object,
    *,
    index: int,
    path: Path,
    source: str,
    tighten_only: bool,
    immutable: bool,
) -> PolicyRule:
    where = f"{path}: rule {index}"
    if not isinstance(item, dict):
        raise PolicyError(f"{where}: must be a table")
    unknown = set(item) - _RULE_KEYS
    if unknown:
        raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

    rule_id = item.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyError(f"{where}: 'id' must be a non-empty string")
    rule_id = rule_id.strip()

    action = item.get("action")
    if action not in ACTIONS:
        raise PolicyError(f"{where}: 'action' must be one of {', '.join(ACTIONS)}")

    reason = item.get("reason")
    if reason is None:
        reason = "blocked by policy" if action == "deny" else "allowed by policy"
    if not isinstance(reason, str) or not reason.strip():
        raise PolicyError(f"{where}: 'reason' must be a non-empty string")

    match = item.get("match")
    contains = item.get("contains")
    if (match is None) == (contains is None):
        raise PolicyError(f"{where}: provide exactly one of 'match' or 'contains'")

    regex = None
    literal = None
    if match is not None:
        if not isinstance(match, str) or not match:
            raise PolicyError(f"{where}: 'match' must be a non-empty string")
        if len(match) > MAX_PATTERN_LENGTH:
            raise PolicyError(
                f"{where}: 'match' is longer than {MAX_PATTERN_LENGTH} characters"
            )
        try:
            regex = re.compile(match)
        except re.error as exc:
            raise PolicyError(f"{where}: invalid regex: {exc}") from exc
    else:
        if not isinstance(contains, str) or not contains:
            raise PolicyError(f"{where}: 'contains' must be a non-empty string")
        literal = contains

    cwd = item.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        raise PolicyError(f"{where}: 'cwd' must be a non-empty glob string")

    ignored = None
    if action == "allow" and tighten_only:
        ignored = "project policies are tighten-only; allow rules are ignored"
    elif action == "allow" and immutable and source in {"user", "project"}:
        ignored = "org policy is immutable; user/project allow rules are ignored"

    return PolicyRule(
        id=rule_id,
        action=action,
        reason=reason.strip(),
        source=source,
        path=path,
        regex=regex,
        contains=literal,
        cwd=cwd,
        ignored=ignored,
    )


def _load_file(
    path: Path, source: str, *, tighten_only: bool, immutable: bool
) -> tuple[list[PolicyRule], PolicyFlags]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{path}: {exc}") from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: invalid TOML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: top-level value must be a table")

    unknown = set(data) - {"version", "policy", "rule"}
    if unknown:
        raise PolicyError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")

    if data.get("version") != 1:
        raise PolicyError(f"{path}: 'version' must be 1")

    flags = PolicyFlags()
    table = data.get("policy", {})
    if not isinstance(table, dict):
        raise PolicyError(f"{path}: [policy] must be a table")
    if table and source not in {"org", "explicit"}:
        raise PolicyError(
            f"{path}: [policy] flags are only allowed in the org policy"
        )
    if source in {"org", "explicit"}:
        flags = PolicyFlags(
            immutable=_as_bool(table, "immutable", path),
            disable_escape_hatch=_as_bool(table, "disable_escape_hatch", path),
            require_key=_as_bool(table, "require_key", path),
        )

    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise PolicyError(f"{path}: [[rule]] must be an array of tables")

    rules: list[PolicyRule] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_rules, 1):
        rule = _parse_rule(
            item,
            index=index,
            path=path,
            source=source,
            tighten_only=tighten_only,
            immutable=immutable,
        )
        if rule.id in seen:
            raise PolicyError(f"{path}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)
    return rules, flags


def load_policy(cwd: str | None = None) -> PolicySet:
    """Load every existing policy source. Raises :class:`PolicyError` on bad input."""
    sources = policy_paths(cwd)
    rules: list[PolicyRule] = []
    flags = PolicyFlags()
    seen_sources: list[tuple[str, Path, bool]] = []

    for source, path in sources:
        exists = path.is_file()
        seen_sources.append((source, path, exists))
        if not exists:
            if source == "explicit":
                raise PolicyError(f"{path}: explicit policy file does not exist")
            continue
        file_rules, file_flags = _load_file(
            path,
            source,
            tighten_only=source == "project",
            immutable=flags.immutable,
        )
        if source in {"org", "explicit"}:
            flags = file_flags
            # Re-evaluate earlier rules if an org file loaded after them (the
            # current order always puts org/explicit first, so this is a no-op).
        rules.extend(file_rules)

    return PolicySet(tuple(rules), flags, tuple(seen_sources))


def _normalize_cwd(value: str) -> str:
    return str(value).replace("\\", "/").rstrip("/").lower() or "/"


def evaluate_policy(
    policy: PolicySet, command: str, cwd: str | None = None
) -> PolicyHit | None:
    """Return the first matching custom rule, or ``None``."""
    if len(command) > MAX_COMMAND_LENGTH:
        return PolicyHit(
            "deny",
            "command-too-long",
            f"command exceeds {MAX_COMMAND_LENGTH} characters",
            "policy",
        )

    pieces = segments(command)
    target_cwd = _normalize_cwd(cwd or os.getcwd())
    for rule in policy.rules:
        if rule.ignored is not None:
            continue
        if rule.cwd is not None and not fnmatch.fnmatchcase(
            target_cwd, _normalize_cwd(rule.cwd)
        ):
            continue
        for piece in pieces:
            matched = (
                rule.regex.search(piece) is not None
                if rule.regex is not None
                else rule.contains in piece  # type: ignore[operator]
            )
            if matched:
                return PolicyHit(rule.action, rule.id, rule.reason, rule.source)
    return None


TEMPLATE = """\
version = 1

# Add as many [[rule]] tables as you need. The first match wins.
# `match` is a Python regex; `contains` is a literal substring. Use exactly one.
#
# [[rule]]
# id = "no-prod-db"
# action = "deny"          # deny | allow
# match = '(?i)\bpsql\b.*\bprod'
# reason = "Production database access is prohibited"
# cwd = "/srv/prod/**"     # optional glob; `*` also matches `/`
"""

ORG_TEMPLATE = """\
version = 1

[policy]
immutable = true            # user/project allow rules are ignored
disable_escape_hatch = true # BASHBOY_DISABLE is ignored
require_key = true          # no key means deny, not local-only

# [[rule]]
# id = "no-prod-db"
# action = "deny"
# match = '(?i)\bpsql\b.*\bprod'
# reason = "Production database access is prohibited"
"""
