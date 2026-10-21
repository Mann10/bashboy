"""Per-user credential file for the Clocked API key.

The token is a bare line in a file (no TOML, no ``KEY=`` prefix) so that
GUI-launched hosts -- which do not inherit a shell profile -- can still find it.

Two policies, both locked by the design brief:

* **POSIX** -- a file with any group/other bits is refused (``mode & 0o077``).
  Failing closed beats silently consuming a leaked secret. The message names
  ``chmod 600 <path>`` so the fix is actionable.
* **Windows** -- ACL problems are advisory. The file lives under the user
  profile, whose default ACL is owner-only; inherited entries from a parent
  directory are normal and refusing would be a support nightmare.

**Hot-path rule:** :func:`read_token` runs on every agent tool call (via
``bashboy check``), so it never spawns a process. On Windows the hot path only
checks that the file exists, is a regular file, is readable, and is non-empty.
The ``icacls`` probe lives behind ``probe_acl=True`` and is used only by
``bashboy auth status``.

This module must not import :mod:`bashboy.config` -- config imports it.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CREDENTIALS_PATH_TOML = "~/.bashboy/credentials"
ENV_API_KEY_FILE = "BASHBOY_API_KEY_FILE"

#: Principals that always have (or legitimately inherit) access on Windows.
_WINDOWS_BASELINE_PRINCIPALS = frozenset(
    {
        "SYSTEM",
        "NT AUTHORITY\\SYSTEM",
        "ADMINISTRATORS",
        "BUILTIN\\ADMINISTRATORS",
        "CREATOR OWNER",
        "OWNER RIGHTS",
        "*S-1-5-18",
        "*S-1-5-32-544",
    }
)


class CredentialError(Exception):
    """The credential file cannot be used or written."""


class CredentialPermissionError(CredentialError):
    """The credential file is readable by users other than its owner."""


class CredentialExistsError(CredentialError):
    """The credential file exists and ``overwrite`` was not requested."""


@dataclass(frozen=True)
class PermissionState:
    """Human-readable (never secret) description of a credential file's access."""

    label: str
    detail: str


def _is_windows() -> bool:
    """Platform seam: tests monkeypatch this to exercise both branches."""
    return os.name == "nt"


def _warn(message: str) -> None:
    """Warn through the stderr logger (``BASHBOY_DEBUG`` only).

    Imported lazily: ``classify`` imports ``config`` which imports this module,
    so a module-level import would be circular.
    """
    from .classify import log

    log(message)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _insecure_message(path: Path, mode: int) -> str:
    return (
        f"{path} has mode {mode:04o}, which is readable by other users; "
        f"run `chmod 600 {path}`"
    )


def permissions(path: Path, *, probe_acl: bool = False) -> PermissionState:
    """Describe ``path``'s access state without reading the token.

    ``probe_acl`` is opt-in so the ``bashboy check`` hot path never spawns a
    process on Windows. POSIX mode bits are a single ``stat`` and are always
    checked.
    """
    target = Path(path)
    if not target.is_file():
        return PermissionState("missing", f"{target} does not exist")

    if _is_windows():
        if not probe_acl:
            # Cheap hot path: existence/regular-file/readability were checked by
            # is_file(); the ACL itself is verified only by `bashboy auth status`.
            return PermissionState(
                "owner-only",
                "owner-only ACL assumed from the user profile; "
                "run `bashboy auth status` to verify",
            )
        extra = _windows_extra_principals(target)
        if extra is None:
            return PermissionState("unverified", "could not verify the file ACL")
        if not extra:
            return PermissionState("owner-only", "owner-only ACL")
        return PermissionState("extra-principals", "ACL grants access to: " + ", ".join(extra))

    mode = _mode(target)
    if mode & 0o077:
        return PermissionState("insecure", _insecure_message(target, mode))
    return PermissionState("owner-only", f"mode {mode:04o}")


def read_token(path: Path) -> str | None:
    """Return the token in ``path``, or ``None`` when missing or empty.

    Read at call time (never cached) so rotation needs no host restart. Raises
    :class:`CredentialPermissionError` on POSIX when the file is group/other
    accessible -- callers must fail closed.
    """
    target = Path(path)
    try:
        info = target.stat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except PermissionError as exc:
        raise CredentialError(f"cannot read {target}: permission denied") from exc
    except OSError as exc:
        raise CredentialError(f"cannot read {target}: {exc}") from exc

    if not stat.S_ISREG(info.st_mode):
        return None

    if not _is_windows():
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise CredentialPermissionError(f"refusing to read {target}: {_insecure_message(target, mode)}")

    try:
        raw = target.read_bytes()
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None
    except PermissionError as exc:
        raise CredentialError(f"cannot read {target}: permission denied") from exc
    except OSError as exc:
        raise CredentialError(f"cannot read {target}: {exc}") from exc

    # Bare token only (D-02): strip whitespace, never parse a `KEY=` prefix.
    text = raw.decode("utf-8", errors="replace").strip()
    return text or None


def write_token(path: Path, token: str, *, overwrite: bool = False) -> None:
    """Write ``token`` to ``path`` atomically with owner-only permissions."""
    target = Path(path)
    value = token.strip()
    if not value or "\n" in value or "\r" in value:
        raise CredentialError("token must be a single non-empty line")

    if target.is_file() and not overwrite:
        raise CredentialExistsError(f"{target} already exists; re-run with --force to overwrite")

    created_parent = not target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    if created_parent and not _is_windows():
        # Only tighten a directory we created -- never a user-chosen --file dir.
        try:
            os.chmod(target.parent, 0o700)
        except OSError:
            pass

    from .installers import atomic_write_text  # lazy: keeps `bashboy check` lean

    atomic_write_text(target, value + "\n")

    if not _is_windows():
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass


def clear_token(path: Path) -> bool:
    """Delete ``path``; return ``True`` if removed and ``False`` if absent."""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return False
    return True


def _windows_extra_principals(path: Path) -> list[str] | None:
    """Return non-baseline principals with full/modify/write access, or ``None``.

    ``None`` means "could not verify" and is treated as a warning, never a
    refusal. Uses the Windows built-in ``icacls`` so no dependency is added;
    ``subprocess`` is imported lazily because this only runs from
    ``bashboy auth status``.
    """
    import subprocess

    try:
        completed = subprocess.run(
            ["icacls", str(path)], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None

    current_user = os.environ.get("USERNAME", "").strip().lower()
    path_text = str(path)
    found: set[str] = set()
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # The first line is "<path> <principal>:(rights)"; continuation lines are
        # indented and start with the principal. Strip our own path first so a
        # principal containing spaces ("NT AUTHORITY\SYSTEM") stays intact.
        if stripped.lower().startswith(path_text.lower()):
            stripped = stripped[len(path_text) :].strip()
        marker = stripped.find(":(")
        if marker <= 0:
            continue
        principal = stripped[:marker].strip()
        if not principal:
            continue
        rights = stripped[marker + 1 :]
        grants = {part.strip("() ") for part in rights.replace(")(", " ").split()}
        if "DENY" in grants or not grants & {"F", "M", "W"}:
            continue
        upper = principal.upper()
        if upper in _WINDOWS_BASELINE_PRINCIPALS:
            continue
        if current_user and principal.rsplit("\\", 1)[-1].strip().lower() == current_user:
            continue
        found.add(principal)
    return sorted(found)
