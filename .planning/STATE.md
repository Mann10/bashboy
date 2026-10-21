# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-21)

**Core value:** Agents cannot run destructive shell commands just because nobody is watching.
**Current focus:** Milestone 1 — working gate, both host integrations.

## Current Position

Phase: 1 of 3 (Classifier core)
Status: Quick tasks 261021-hu8 and 261021-iz1 delivered the v0.1 implementation and v0.2 file-based credentials
Last activity: 2026-10-21 - Completed quick task 261021-iz1: file-based Clocked credentials (v0.2.0)

Progress: [███████---] 75%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0 hours

## Accumulated Context

### Decisions

- Stdlib-only HTTP client for fast hook startup.
- Verdict is binary: allow (no decision) or deny.
- Fail closed on provider errors.
- Allowlist matches only single simple commands (no shell operators).

### Pending Todos

- Validate the Clocked response envelope with a real `CLOCKED_API_KEY`.

### Releases

- `0.1.0` published to PyPI on 2026-10-21 via GitHub trusted publishing
  (`.github/workflows/release.yml`, tag `v0.1.0`).
- `0.2.0` implemented (file-based credentials + `bashboy auth`), not yet published.
  Release with `git tag -a v0.2.0 -m "bashboy 0.2.0" && git push origin v0.2.0`.

### Blockers/Concerns

- Clocked endpoint (`POST https://clocked.rezolve.ai/clocked/fill`) response shape is
  unverified; the adapter must be tolerant and tested against fixtures.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 261021-hu8 | Build BashBoy: uv/uvx Python CLI classifying shell commands via Clocked with local fast paths + Claude Code and OpenCode integrations | 2026-10-21 | d50abc0 | [261021-hu8-build-bashboy-a-uv-uvx-python-cli-that-c](./quick/261021-hu8-build-bashboy-a-uv-uvx-python-cli-that-c/) |
| 261021-iz1 | Add file-based Clocked credentials: `api_key_file`, `BASHBOY_API_KEY_FILE`, `bashboy auth set/status/clear` | 2026-10-21 | f15f007 | [261021-iz1-add-file-based-clocked-credentials-provi](./quick/261021-iz1-add-file-based-clocked-credentials-provi/) |
