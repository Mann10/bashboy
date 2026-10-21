# BashBoy — File-based credentials (locked decisions)

Orchestrator-supplied design brief for quick task `261021-iz1`. Treat every decision as locked
unless it is technically impossible. Builds on the shipped v0.1.0 (226 tests, PyPI-published).

## Problem

The Clocked API key can only come from an environment variable. That breaks two real cases:

1. GUI-launched hosts (Claude Code desktop, OpenCode's background service) do not inherit a shell
   profile, so `$env:CLOCKED_API_KEY` set in a terminal is invisible to them.
2. `setx` exposes the key to every process on the machine and is painful to rotate.

A per-user file with strict permissions gives every host a reliable source without a machine-wide
env var, and without putting a secret in `config.toml` (which is shareable and gets pasted into
issues).

## Locked behaviour

### Resolution order (first hit wins)

1. Environment variable named by `[provider].api_key_env` (default `CLOCKED_API_KEY`).
2. `BASHBOY_API_KEY_FILE` (environment override, full path).
3. `[provider].api_key_file` (TOML, `~` expanded).
4. Default file `~/.bashboy/credentials`.
5. Nothing → no key → model-path calls fail closed (`deny` / `source=fallback`).

Backwards compatibility is mandatory: an existing env-var-only setup must behave exactly as today.

### Credential file

- Contents: a single token, surrounding whitespace stripped. No TOML, no `KEY=` prefix.
- Missing file → no key (not an error).
- Empty/whitespace-only file → no key.
- **POSIX:** refuse to use a file with any group/other permission bits (`mode & 0o077`). Raise a
  clear error telling the user to `chmod 600 <path>`. Failing closed beats silently consuming a
  leaked secret.
- **Windows:** verify the ACL is owner-only; if extra principals are present, **warn only** (via
  the stderr `log()` helper), never refuse. Windows ACL inheritance makes hard refusal a support
  nightmare, and the file lives under the user profile, whose default ACL is already owner-only.
- Read at call time, never cached at import or module load, so rotation needs no host restart.

### CLI

```
bashboy auth set   [--file PATH] [--stdin] [--force]
bashboy auth status [--file PATH] [--check]
bashboy auth clear [--file PATH] [--force]
```

- `auth set`
  - Default target: `[provider].api_key_file` if configured, else `~/.bashboy/credentials`.
  - Interactive: prompt with `getpass.getpass` (never echoed). Confirm by re-prompting once.
  - `--stdin`: read the token from stdin (for provisioning scripts and CI). Never accept the token
    as a command-line argument — it would land in shell history and process listings.
  - Empty token → error, exit 2, nothing written.
  - Existing file: refuse without `--force`.
  - Write atomically, create `~/.bashboy` if needed, set `0600` on POSIX (best effort on Windows).
  - Then validate with one real provider call using a benign command (`git status`) and print
    `provider: ok` or `provider: FAILED (<reason>)`. The file stays saved either way.
    Exit 0 when saved and validated, exit 2 when saved but validation failed.
  - Never print the token, any prefix of it, or its length.
- `auth status` (always exit 0 unless config is unreadable)
  - Prints: config path, endpoint, key source, whether a key is present, and the file's
    permission state.
  - Source rendering: `env CLOCKED_API_KEY`, `file C:\...\.bashboy\credentials (owner-only)`, or
    `none`.
  - `--check` performs one live provider call and reports `provider: ok|FAILED (...)`; without the
    flag it makes no network call.
  - Never prints the value.
- `auth clear`
  - Deletes the resolved file after a confirmation prompt; `--force` skips it. Missing file is a
    no-op success with a clear message.
- `ConfigError` → message on stderr, exit 2.
- stdout stays reserved for the human summary; warnings/backups go to stderr.

### Config additions

```toml
[provider]
endpoint = "https://clocked.rezolve.ai/clocked/fill"
api_key_env = "CLOCKED_API_KEY"
api_key_file = "~/.bashboy/credentials"   # optional; defaults to this path
timeout_ms = 4000
```

- `ProviderConfig.api_key_file: Path` — always resolved (default `~/.bashboy/credentials`), `~`
  expanded, no existence requirement.
- Env override `BASHBOY_API_KEY_FILE` wins over TOML.
- Add `resolve_api_key(cfg) -> tuple[str | None, str]` returning `(value, source_label)`.
  Keep `api_key(cfg) -> str | None` delegating to it so existing callers and tests keep working.
- Malformed values raise `ConfigError` (never a silent fallback).

### Error message quality

When no key is available, the fallback reason must be actionable, e.g.

```
classifier unavailable: no API key configured (set CLOCKED_API_KEY or run `bashboy auth set`)
```

Update existing tests that assert the old string.

## Files

```
src/bashboy/credentials.py          # new: read/write/clear + permission checks
src/bashboy/config.py               # api_key_file, resolve_api_key, BASHBOY_API_KEY_FILE
src/bashboy/classify.py             # use resolve_api_key, actionable reason
src/bashboy/cli.py                  # auth set|status|clear
src/bashboy/provider.py             # optional: expose a one-shot verify helper (no behaviour change)
tests/test_credentials.py           # new
tests/test_config.py                # api_key_file precedence/expansion
tests/test_cli.py                   # auth subcommands
tests/test_classify.py              # updated reason string, file-sourced key
README.md                           # credentials section, precedence table, permissions, Windows note
pyproject.toml                      # version 0.2.0
```

## Test matrix (offline, no real key)

1. Env var wins over file; file used when env absent; `BASHBOY_API_KEY_FILE` wins over TOML.
2. Missing file → no key; empty file → no key; whitespace-only → no key.
3. POSIX world-readable file (`0o644`) → refused with a `chmod 600` message (skip on Windows).
4. POSIX `0600` file → accepted.
5. Windows branch: extra ACL principals → warn, still accepted (monkeypatch the platform check).
6. `auth set --stdin` writes the file; `auth status` shows the path and source, never the token;
   a second `set` without `--force` refuses; `--force` overwrites.
7. `auth clear --force` removes the file; clearing a missing file succeeds.
8. `auth set` with an empty token exits 2 and writes nothing.
9. `classify_command` uses a file-sourced key (fake provider), and the no-key reason mentions
   `bashboy auth set`.
10. No test output ever contains the sample token value (assert on captured capsys output).

## Security constraints

- The token must never be passed as an argv element, printed, logged, or embedded in an exception.
- Writes are atomic (temp file in the target directory + `os.replace`), reusing the installer helper.
- `~/.bashboy` directory is created with `0700` on POSIX.
- No new runtime dependencies; stdlib only (`getpass`, `os`, `stat`, `subprocess` only if strictly
  needed — prefer a pure-Python ACL probe on Windows and warn-only semantics).
- Do not change the fail-closed policy, the binary verdict, or the deny-only host integrations.

## Acceptance

```powershell
echo "test-token" | uv run bashboy auth set --stdin --file "$env:TEMP\bb-cred" --force
uv run bashboy auth status --file ...        # shows file source, never the token
uv run bashboy check --command "docker run --rm alpine sh"   # no env, file has bogus key -> deny/fallback
uv run python -c "import os; os.chmod(...)"  # POSIX-only permission test lives in pytest
uv run pytest -q                              # all green, offline
```

Version bumps to `0.2.0`. Do not tag or publish; the orchestrator leaves release to the user.

## Constraints

- 1–2 tasks, atomic commits.
- Update README: precedence table, `auth` commands, permissions policy, Windows note, and remove
  the claim that env vars are the only source.
- Keep `bashboy --help` and every existing command's output contract unchanged.
