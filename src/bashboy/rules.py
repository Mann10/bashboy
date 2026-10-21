"""Structural allowlist and hard denylist fast paths.

Both functions are pure: no I/O, no environment reads, no imports beyond the
standard library's ``re`` and ``dataclasses``. They run before any model call,
so the hook path stays fast and offline.

The allowlist is deliberately structural. A command is only allowlisted when it
contains no shell operators, substitutions, redirections, or chaining -- a
command that merely *looks* like ``ls`` but smuggles a second command is never
allowlisted. False negatives (falling through to the model) are safe; false
positives are not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Shell metacharacters that make a command structurally unsuitable for the
# allowlist. This deliberately excludes glob characters (``*``, ``?``, ``~``,
# ``[``), which cannot start a new command or substitute one, and is required to
# keep read-only forms such as ``find . -name '*.py'`` and ``git diff HEAD~1``
# allowlistable.
SHELL_METACHARS = frozenset(";|&$`<>(){}\\\n\r\x00")

_SIMPLE_HEADS = frozenset(
    {"ls", "pwd", "cat", "head", "tail", "wc", "grep", "rg", "find", "echo", "which", "whoami", "date"}
)
_GIT_SUBCOMMANDS = frozenset({"status", "diff", "log", "show", "branch"})
_VERSION_HEADS = frozenset({"uv", "python", "node"})
# ``find`` is read-only until it is asked to execute or delete something.
_FIND_EXEC_FLAGS = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete"})

_SPLIT_SEGMENTS = re.compile(r";|&&|\|\||\||\r?\n")
_MAX_SEGMENT_DEPTH = 5


@dataclass(frozen=True)
class DenyHit:
    """A denylist match: what rule fired and why."""

    reason: str
    pattern: str


def _command_substitutions(command: str) -> list[str]:
    """Return the bodies of ``$( ... )`` and backtick substitutions."""
    bodies: list[str] = []
    i = 0
    length = len(command)
    while i < length:
        ch = command[i]
        if ch == "`":
            end = command.find("`", i + 1)
            if end == -1:
                break
            bodies.append(command[i + 1 : end])
            i = end + 1
            continue
        if ch == "$" and i + 1 < length and command[i + 1] == "(":
            depth = 0
            j = i + 1
            while j < length:
                if command[j] == "(":
                    depth += 1
                elif command[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < length:
                bodies.append(command[i + 2 : j])
                i = j + 1
                continue
        i += 1
    return bodies


def segments(command: str) -> list[str]:
    """Split a command into the raw string plus every executable fragment.

    Fragments are split on ``;``, ``&&``, ``||``, ``|`` and newlines, and the
    bodies of command substitutions are added (recursively, capped at 5 levels).
    """
    return _segments(command, 0)


def _segments(command: str, depth: int) -> list[str]:
    out = [command]
    if depth >= _MAX_SEGMENT_DEPTH:
        return out
    for piece in _SPLIT_SEGMENTS.split(command):
        if piece.strip():
            out.append(piece)
    for body in _command_substitutions(command):
        out.extend(_segments(body, depth + 1))
    return out


# --- denylist -------------------------------------------------------------

_RM_PREFIX = r"(?<![-\w])rm\s+(?:(?:-[A-Za-z]+|--[\w-]+)\s+)+"

# Protected targets: filesystem root, root glob, system directories, home.
_RM_PROTECTED_TARGET = (
    r"(?:"
    r"/(?=\s|$)"
    r"|/\*"
    r"|/(?:usr|etc|var|bin|sbin|boot|lib|lib64|opt|root|home|srv|sys|dev|proc)\b\S*"
    r"|~(?=\s|$)"
    r"|~/(?=\s|$)"
    r"|~/\*"
    r"|\$(?:HOME|\{HOME\})(?=\s|$|/)"
    r")"
)

_RM_PROTECTED = re.compile(_RM_PREFIX + _RM_PROTECTED_TARGET, re.IGNORECASE)
_RM_WILDCARD = re.compile(_RM_PREFIX + r"(?:\./)?\*(?=\s|$)", re.IGNORECASE)

DENY_RULES: list[tuple[re.Pattern[str], str]] = [
    (_RM_PROTECTED, "recursive delete of a protected path"),
    (_RM_WILDCARD, "recursive delete of a wildcard target at the filesystem root"),
    (re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b", re.IGNORECASE), "filesystem creation on a device"),
    (re.compile(r"\b(?:fdisk|parted|diskpart)\b", re.IGNORECASE), "disk partitioning"),
    (re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE), "drive format"),
    (re.compile(r"\bdd\b[^\n]*\bof=/dev/", re.IGNORECASE), "raw write to a block device"),
    (re.compile(r">\s*/dev/(?:sd|hd|nvme|disk|vd)", re.IGNORECASE), "raw write to a block device"),
    (re.compile(r"\bshred\b[^\n]*/dev/", re.IGNORECASE), "shred of a block device"),
    (
        re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*&\s*\}\s*;\s*:", re.IGNORECASE),
        "fork bomb",
    ),
    (re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*777\s+/(?=\s|$)", re.IGNORECASE), "world-writable root"),
    (re.compile(r"\bchown\s+(?:-[a-zA-Z]+\s+)*\S+\s+/(?=\s|$)", re.IGNORECASE), "ownership change on root"),
    (re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b", re.IGNORECASE), "host power control"),
    (
        re.compile(
            r"remove-item\b[^\n]*-recurse[^\n]*(?:[a-z]:[\\/]?\s*$|\s/[\"']?\s*$)",
            re.IGNORECASE,
        ),
        "recursive delete of a drive root",
    ),
    (
        re.compile(
            r"\bgit\s+clean\s+-[a-zA-Z]*[fdx][a-zA-Z]*[^\n]*(?:\s/(?=\s|$)|\s--\s+/)",
            re.IGNORECASE,
        ),
        "git clean at the filesystem root",
    ),
]

# ``rm -rf *`` only denies when it would run at a filesystem root, where the
# glob expands to the whole disk. Elsewhere the model decides.
_CWD_GATED = frozenset({_RM_WILDCARD.pattern})

_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


def _at_filesystem_root(cwd: str | None) -> bool:
    if cwd is None:
        return True
    stripped = cwd.strip()
    if stripped in {"/", "\\", ""}:
        return True
    return bool(_DRIVE_ROOT.match(stripped))


def check_denylist(command: str, cwd: str | None = None) -> DenyHit | None:
    """Return the first denylist hit, or ``None``.

    The raw command, every operator-split segment, and every command-substitution
    body are scanned, so payloads hidden in compound commands are caught.
    """
    if not isinstance(command, str) or not command.strip():
        return None
    pieces = segments(command)
    for piece in pieces:
        for pattern, reason in DENY_RULES:
            if pattern.search(piece) is None:
                continue
            if pattern.pattern in _CWD_GATED and not _at_filesystem_root(cwd):
                continue
            return DenyHit(reason=reason, pattern=pattern.pattern)
    return None


# --- allowlist ------------------------------------------------------------


def check_allowlist(command: str) -> str | None:
    """Return a stable label when the command is a single allowlisted program."""
    if not isinstance(command, str):
        return None
    cmd = command.strip()
    if not cmd:
        return None
    if any(ch in SHELL_METACHARS for ch in cmd):
        return None

    tokens = cmd.split()
    if not tokens:
        return None
    head = tokens[0]

    if head == "cd":
        # ``cd`` with at most one plain argument.
        return "cd" if len(tokens) <= 2 else None

    if head in _SIMPLE_HEADS:
        if head == "find" and any(tok.lower() in _FIND_EXEC_FLAGS for tok in tokens[1:]):
            return None
        return head

    if head in _VERSION_HEADS:
        if len(tokens) == 2 and tokens[1] == "--version":
            return f"{head} --version"
        return None

    if head == "git":
        sub = next((tok for tok in tokens[1:] if not tok.startswith("-")), None)
        if sub in _GIT_SUBCOMMANDS:
            return f"git {sub}"
        return None

    return None
