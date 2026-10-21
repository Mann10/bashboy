---
phase: 261021-hu8
status: complete
date: 2026-10-21
---

# BashBoy: a uv/uvx Python CLI deny-gate for agent shell commands

BashBoy 0.1.0 built end to end: stdlib-only classifier with structural allowlist, hard
denylist (compound-injection aware), Clocked model fallback that fails closed, deny-only Claude
Code `PreToolUse` hook and OpenCode V2/V1 plugin, idempotent non-clobbering installers, and a
226-test offline suite.

## Files created

Package (source lines):

| File | Lines | Role |
|------|-------|------|
| `pyproject.toml` | 27 | hatchling metadata, `bashboy` console script, `dependencies = []`, pytest config |
| `uv.lock` | — | dev-only lock (pytest) for reproducible `uv run` |
| `src/bashboy/__init__.py` | 5 | `__version__ = "0.1.0"`, no submodule imports |
| `src/bashboy/__main__.py` | 5 | `python -m bashboy` |
| `src/bashboy/config.py` | 219 | `DEFAULT_CONFIG_TOML`, frozen config dataclasses, env overrides, hard `ConfigError` |
| `src/bashboy/rules.py` | 225 | structural `check_allowlist`, `segments`, `check_denylist`, `DENY_RULES` (pure) |
| `src/bashboy/provider.py` | 215 | `RUBRIC`, `build_request_body`, BFS `extract_field`, injectable transport, `Provider` |
| `src/bashboy/classify.py` | 124 | `classify_command` precedence, lazy provider import, `log()` to stderr |
| `src/bashboy/cli.py` | 271 | `check`/`install`/`config`/`selftest`/`version` |
| `src/bashboy/hooks/claude.py` | 92 | `run_hook`, `parse_hook_payload`, `parse_hook_cwd`, `deny_payload` |
| `src/bashboy/installers/__init__.py` | 38 | `atomic_write_text` (temp file + `os.replace`) |
| `src/bashboy/installers/claude.py` | 135 | idempotent `settings.json` merge, `.bak`, atomic write |
| `src/bashboy/installers/opencode.py` | 199 | `PLUGIN_SOURCE` (TS), plugin write + `opencode.json` registration |
| `README.md` | 281 | all 11 required sections |

Tests (226 tests, all offline; 1,359 test lines):

`tests/conftest.py` (ambient env isolation + temp `BASHBOY_CONFIG`), `tests/test_rules.py`,
`tests/test_config.py`, `tests/test_provider.py`, `tests/test_classify.py`,
`tests/test_claude_hook.py`, `tests/test_cli.py`, `tests/test_installers.py`.

## Test count

`uv run pytest` → **226 passed in 0.81s**, exit 0, with `CLOCKED_API_KEY` unset and no network
calls (fake transport, `monkeypatch`ed `urlopen`, `io.StringIO` streams, `tmp_path` installs).

## Verification results

| # | Check | Result |
|---|-------|--------|
| 1 | `uv run pytest -q` | PASS — 226 passed, offline |
| 2 | `check --command "rm -rf /" --json` | PASS — exit 1, `deny`/`denylist`, `latency_ms: 0` |
| 3 | `check --command "git status" --json` | PASS — exit 0, `allow`/`allowlist` |
| 4 | `check --command "docker run --rm alpine sh" --json` (no key) | PASS — exit 1, `deny`/`fallback` |
| 5 | `check --command "ls; rm -rf /" --json` | PASS — exit 1, `deny`/`denylist` |
| 6 | hook deny / hook allow | PASS — deny envelope with `permissionDecision: "deny"`, exit 0; allow → empty stdout, exit 0 |
| 7 | `install --claude --dry-run --settings <tmp>` | PASS — valid settings JSON, args `["bashboy","check","--claude-hook"]`, no file created |
| 8 | `install --opencode --dry-run --config-dir <tmp>` | PASS — valid JSON, plugin source has `execute.before` + `BashBoy blocked`, no files created |
| 9 | `selftest` (no key) | PASS — 3/3 checks, `provider: skipped`, exit 0 |
| 10 | `config init` (temp `BASHBOY_CONFIG`) | PASS — created (exit 0), second run refuses (exit 1), `--force` overwrites |
| 11 | `version` | PASS — `bashboy 0.1.0 (python 3.12.6)`, exit 0 |

Additional end-to-end checks (not in the numbered list):

- `uvx --from . bashboy check --command "git status" --json` → allow/allowlist, exit 0.
- Two real `install --claude` runs against a temp file → exactly 1 handler, `.bak` present,
  unrelated keys intact.
- Two real `install --opencode` runs against a temp dir → 1 plugin entry, `$schema` present,
  `plugins/bashboy.ts` written.

## Deviations from the plan

1. **SHELL_METACHARS narrowed (required for the stated behaviours).** The plan listed
   `* ? ~ # [ "` as metacharacters, but that makes two mandated allowlist behaviours
   impossible: `find . -name '*.py'` → `"find"` and `git diff HEAD~1` → `"git diff"` both
   contain those characters. The gate now rejects only characters that can start a new
   command, substitute one, redirect output, or break quoting: ``; | & $ ` < > ( ) { } \ \n \r \0``.
   This is not a loosening of the security property: glob/tilde characters cannot execute or
   chain anything, and the allowlisted heads are read-only programs. Covered by tests
   (`find . -name '*.py'`, `git diff HEAD~1`, plus all the rejected operator cases).

2. **`find` execution guard (Rule 2, hardening).** `find` is allowlisted, so `find . -delete`
   and `find . -exec rm {} ;` would otherwise be allowlisted. Any `-exec`, `-execdir`, `-ok`,
   `-okdir`, or `-delete` token now disqualifies `find` from the allowlist (falls through to
   the model). Tests: `find . -delete`, `find . -exec rm {} ;` → `None`.

3. **TDD gates were not split into separate commits.** Tasks 1 and 2 are `tdd="true"`, but each
   task's `<done>` block names a single commit and `success_criteria` requires "exactly three
   atomic commits, one per task". Tests were authored before implementation within each task;
   RED/GREEN were not committed separately. Documented here rather than adding three extra
   commits.

4. **`config init` refusal exit code.** The plan says "refusing to overwrite unless `--force`"
   without an exit code. Refusal exits **1** (a refusal is not success, and 2 is reserved for
   config/usage errors). `--force` exits 0.

5. **`install` with no flag** installs both integrations (equivalent to `--all`). The BRIEF's
   CLI grammar leaves the no-flag case undefined; requiring an explicit flag seemed likelier to
   strand users than to protect them, and both paths are idempotent.

6. **OpenCode plugin reads deny JSON from `error.stdout`.** The CLI exits 1 on deny (per the
   locked CLI contract), so `execFile` rejects even for a well-formed deny payload. The plugin
   parses stdout from the rejection first and only fails closed when there is no parseable JSON.
   This is required for the integration to work at all; it does not auto-allow any path.

No runtime dependencies were added (`dependencies = []`), and no cache, audit log, web UI,
`ask` verdict, or auto-approve behaviour exists.

## Commits

| Task | Commit |
|------|--------|
| 1 | `feat(bashboy): scaffold package, config loader, and fast-path rules` |
| 2 | `feat(bashboy): add Clocked provider, classifier, CLI, and Claude hook` |
| 3 | `feat(bashboy): add Claude/OpenCode installers, docs, and E2E acceptance` |
