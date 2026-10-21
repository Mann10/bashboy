---
phase: 261021-iz1
plan: 01
status: complete
date: 2026-10-21
title: File-based Clocked credentials (provider.api_key_file, BASHBOY_API_KEY_FILE, bashboy auth)
tags: [credentials, cli, config, security]
key-files:
  created:
    - src/bashboy/credentials.py
    - tests/test_credentials.py
  modified:
    - src/bashboy/config.py
    - src/bashboy/classify.py
    - src/bashboy/provider.py
    - src/bashboy/cli.py
    - tests/conftest.py
    - tests/test_config.py
    - tests/test_classify.py
    - tests/test_provider.py
    - tests/test_cli.py
    - README.md
    - pyproject.toml
    - src/bashboy/__init__.py
    - uv.lock
metrics:
  tasks: 2
  commits: 2
  tests_before: 226
  tests_after: 287
  tests_passed: 279
  tests_skipped: 8
---

# Quick 261021-iz1: File-based Clocked credentials

The Clocked API key can now be read from a per-user credential file, with
`bashboy auth set|status|clear` managing it; env-var-only installs behave exactly
as v0.1.0 did.

## Resolution order (implemented)

First hit wins, in `config.resolve_api_key(cfg) -> (token, source_label)`:

| # | Source | Source label |
|---|--------|--------------|
| 1 | `CLOCKED_API_KEY` (or `[provider].api_key_env`) | `env CLOCKED_API_KEY` |
| 2 | `BASHBOY_API_KEY_FILE` | `file <path> (<state>)` |
| 3 | `[provider].api_key_file` (TOML, `~` expanded) | `file <path> (<state>)` |
| 4 | `~/.bashboy/credentials` | `file <path> (<state>)` |
| 5 | nothing | `none` |

`BASHBOY_API_KEY_FILE` and the TOML value collapse into
`ProviderConfig.api_key_file` at load time, so the runtime order is exactly
1 → resolved-file → 5. `api_key(cfg)` delegates to `resolve_api_key(cfg)[0]`.

## Public API

```python
# src/bashboy/credentials.py (stdlib only; imports nothing from .config)
DEFAULT_CREDENTIALS_PATH_TOML = "~/.bashboy/credentials"
ENV_API_KEY_FILE = "BASHBOY_API_KEY_FILE"

class CredentialError(Exception)
class CredentialPermissionError(CredentialError)
class CredentialExistsError(CredentialError)

@dataclass(frozen=True)
class PermissionState:
    label: str    # missing | owner-only | insecure | extra-principals | unverified
    detail: str   # human sentence, never the token

def permissions(path, *, probe_acl: bool = False) -> PermissionState
def read_token(path) -> str | None
def write_token(path, token, *, overwrite: bool = False) -> None
def clear_token(path) -> bool

# src/bashboy/config.py
DEFAULT_API_KEY_FILE = "~/.bashboy/credentials"
ProviderConfig(endpoint, api_key_env, api_key_file, timeout_ms)   # api_key_file is a Path
def resolve_api_key(cfg) -> tuple[str | None, str]

# src/bashboy/provider.py
def verify_key(cfg: ProviderConfig, key: str, cwd: str | None = None) -> Verdict
```

## Permission policy as implemented

**POSIX**
- `read_token` refuses (`CredentialPermissionError`) when `mode & 0o077`, message:
  `refusing to read <path>: <path> has mode 0644, which is readable by other users; run `chmod 600 <path>``.
- `classify_command` resolves the key inside its fail-closed `try`, so a refusal
  becomes `deny` / `source=fallback` naming `chmod 600` — never a traceback.
- `write_token` creates a missing parent at `0700` (only a directory it created),
  writes atomically via `installers.atomic_write_text`, then `chmod 0600`
  (best effort).
- Other commands exit 2 on a refusal through `main`'s
  `except (ConfigError, CredentialError)`.

**Windows**
- Hot path (`bashboy check`, i.e. `read_token`/`resolve_api_key`/`classify_command`):
  only exists + regular file + readable + non-empty. **No subprocess.**
- `permissions(path)` (hot path) reports `owner-only` with the detail
  `owner-only ACL assumed from the user profile; run `bashboy auth status` to verify`.
- `permissions(path, probe_acl=True)` — used **only** by `bashboy auth status` —
  runs `icacls` via `subprocess` (imported lazily inside the probe), parses grants
  for bare `F`/`M`/`W`, ignores `SYSTEM`, `Administrators`, `CREATOR OWNER`,
  `OWNER RIGHTS`, the S-1-5-18/544 SIDs and the current user, and reports
  `extra-principals` (warning only; the key is still used) or `unverified` when
  `icacls` fails.

## CLI

| Command | Exit | Behaviour |
|---------|------|-----------|
| `auth set --stdin` / `auth set` | 0 | saved + `provider: ok` |
| `auth set` (file exists, no `--force`) | 1 | refuses, file untouched |
| `auth set` (empty token / mismatch / write error) | 2 | nothing written |
| `auth set` (saved, validation failed) | 2 | `provider: FAILED (...)`, file kept |
| `auth status` | 0 | path, endpoint, source, presence, permissions; no network |
| `auth status --check` | 0 | adds `provider: ok|FAILED (...)` or `skipped` |
| `auth clear --force` | 0 | removed; missing file is a no-op success |
| `auth clear` answered `n` | 1 | aborted, file kept |
| `auth` with no action | 2 | usage on stderr |

The token is accepted only from `getpass` or `--stdin`; there is no `--token`
flag or positional. Nothing prints the token, a prefix, or its length.

## Verification

- `uv run pytest -q` → **279 passed, 8 skipped** (skips are POSIX-only
  permission assertions), fully offline (no sockets; `verify_key` is patched in
  every CLI test).
- `uv run bashboy --help` → `check, install, config, auth, selftest, version`.
- `uv run bashboy version` → `bashboy 0.2.0 (python 3.12.6)`.
- `uv run bashboy selftest` → `3/3 checks passed`, `provider: skipped (no API key)`.
- Manual smoke against a closed port: `auth set` saved + `provider: FAILED`
  (exit 2), `auth status` exit 0 with file source and no network, `auth clear
  --force` removed then no-op, `config show` emits a valid TOML `api_key_file`
  line with escaped Windows backslashes.
- End-to-end file resolution: with `BASHBOY_API_KEY_FILE` set,
  `bashboy check --command "docker build ."` reached the provider (HTTP 403 for
  the bogus smoke token) instead of the "no API key" fallback.

## Test count delta

226 → 287 collected (+61): `test_credentials.py` (31 new), `test_config.py`
(+11), `test_classify.py` (+4), `test_cli.py` (+18), `test_provider.py` unchanged
count (assertion extended).

## Deviations from BRIEF.md / PLAN.md

1. **[Hot-path rule, orchestrator override] Windows ACL probe confined to `auth status`.**
   `read_token`/`resolve_api_key`/`classify_command` never spawn a process; they
   perform only existence/regular-file/readability/non-emptiness checks. The
   probe is reachable only through `permissions(path, probe_acl=True)`, which the
   CLI calls from `_cmd_auth_status`. Consequence: `read_token` does **not** emit
   the D-04 warning itself; `auth status` reports extra principals in its
   `permissions:` line and also emits a `log()` warning (visible under
   `BASHBOY_DEBUG`). Warn-only semantics (never refuse) are preserved.
2. **[Interface addition]** `permissions()` gained the keyword-only
   `probe_acl: bool = False` parameter to keep the hot path cheap. Existing
   call sites use the default.
3. **[Implementation detail]** `subprocess` is imported lazily inside
   `_windows_extra_principals` rather than at module import, so `bashboy check`
   startup does not pay for it. `icacls` remains the probe mechanism (expected
   deviation: no ctypes ACL implementation).
4. **[Correctness]** `auth status --file X` also overrides the *resolution*
   source (via `dataclasses.replace`), not just the reported path. Without this,
   `status --file` would report the default file's source, contradicting the
   brief's `key source: file <path>` requirement.
5. **[Correctness]** `config show` escapes backslashes when rendering
   `api_key_file` (`_toml_string`), so Windows paths stay valid TOML. The line is
   additive and only the path is rendered — never the token.
6. **[Reporting accuracy]** When the probed ACL state is `extra-principals` or
   `unverified`, `auth status` reports that state in `key source:` instead of the
   hot-path `owner-only` assumption; the `permissions:` line already carried it.
7. **[Commit hygiene]** Task 1's commit was amended (`4d747b4`) to fold in the
   `icacls` principal-parsing fix (names containing spaces such as
   `NT AUTHORITY\SYSTEM`) and its unit tests. Still two atomic commits.
8. **[Test isolation]** `tests/conftest.py` sets `BASHBOY_API_KEY_FILE` to a
   non-existent temp path; `tests/test_config.py` deletes it per test (so TOML
   defaults are testable) and explicitly points the two resolution tests at an
   absent file, so a developer's real `~/.bashboy/credentials` can never affect
   the suite.
9. **[Expected per plan output]** `auth set` refusal on an existing file returns
   **1**, mirroring `config init`; validation failure returns 2.

## Known stubs

None. No placeholder data, TODOs, or unwired paths were introduced.

## Threat flags

None beyond the plan's threat register. No new network endpoint or trust
boundary was added; `auth set` reuses the existing provider transport.

## Self-Check: PASSED

- `src/bashboy/credentials.py` exists (task 1 commit `4d747b4`).
- `tests/test_credentials.py`, `tests/test_cli.py`, `README.md`, `uv.lock` all present in the two commits.
- Commits verified: `4d747b4`, `f15f007` on `main`; `.planning/**` intentionally left uncommitted.
- `uv run pytest -q` → 279 passed, 8 skipped, exit 0.

