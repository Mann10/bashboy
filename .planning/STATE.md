# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-21)

**Core value:** Agents cannot run destructive shell commands just because nobody is watching.
**Current focus:** Milestone 1 — working gate, both host integrations.

## Current Position

Phase: 1 of 3 (Classifier core)
Status: v0.3.1 shipped; 0.4.0 adds local-only mode and a browsable rule catalog
Last activity: 2026-10-21 - Added local-only mode and `bashboy rules` (0.4.0)

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
- Clocked requests send `User-Agent: bashboy/<version>`: Cloudflare answers 403
  (error 1010) to urllib's default signature, which looked like a bad token.
- Live envelope (verified 2026-10-21): `{"model":"clocked-1.0","fields":{"verdict":{"value":"allow",...},"risk":{"value":"low",...},"reason":{"value":"yes",...}},"timing":{...}}`.
- Denylist accepts quoted destructive targets (`rm -rf "/"`, `rm -rf '/usr'`).
- Dotenv protection is command-position based: `cat .env`, `cp .env /tmp`, and
  `echo x > .env` are denied; `git commit -m "fix .env"` is not. Claude's `Read`
  tool is guarded by path; `.env.example`/`.env.sample`/`.env.template` stay readable.
- Adopted the command-position idea from `safety-hooks` (pchalasani/claude-code-tools,
  MIT), not its code. Deliberate divergences: binary verdict (no `ask`), fail closed
  (no `{"decision":"approve"}` fallback), no alias expansion, no file-length hook.
- No API key means **local-only**: the denylist/allowlist still run, known-bad is
  denied, and unknown commands get no objection (the host's permission flow decides).
  `BASHBOY_REQUIRE_KEY=1` turns unknown commands into `deny/fallback`.
- A single `RULES` catalog drives both enforcement and `bashboy rules`; the dotenv
  rule is code-based (`pattern=None`) and listed alongside the regex rules.
- Added basic Windows recursive deletes (`del /s`, `rd /s`), `find / -delete`,
  `wipefs`/`blkdiscard`, and environment-dump rules (`printenv`, bare `env`/`set`,
  `export -p`, `/proc/*/environ`, PowerShell `Env:`).

### Pending Todos

- Publish `0.4.0` (local-only mode + `bashboy rules`) and confirm `uvx bashboy version`.
- Optional: gate OpenCode's `read` tool the same way as Claude's `Read` (currently only shell tools are hooked there).

### Releases

- `0.1.0` published to PyPI on 2026-10-21 via GitHub trusted publishing
  (`.github/workflows/release.yml`, tag `v0.1.0`).
- `0.2.0` published to PyPI on 2026-10-21 (file-based credentials + `bashboy auth`);
  it fails every provider call with HTTP 403 because of Cloudflare error 1010.
- `0.2.1` fixes the User-Agent; published 2026-10-21, `uvx bashboy version` confirmed.
- `0.3.0` added the dotenv guard and quoted destructive-target matching; `0.3.1`
  added Windows drive-root deletes. Neither is tagged.
- `0.4.0` adds local-only mode and the `bashboy rules` catalog; tag pending.

### Blockers/Concerns

- None. The Clocked response envelope is verified against a live call.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 261021-hu8 | Build BashBoy: uv/uvx Python CLI classifying shell commands via Clocked with local fast paths + Claude Code and OpenCode integrations | 2026-10-21 | d50abc0 | [261021-hu8-build-bashboy-a-uv-uvx-python-cli-that-c](./quick/261021-hu8-build-bashboy-a-uv-uvx-python-cli-that-c/) |
| 261021-iz1 | Add file-based Clocked credentials: `api_key_file`, `BASHBOY_API_KEY_FILE`, `bashboy auth set/status/clear` | 2026-10-21 | f15f007 | [261021-iz1-add-file-based-clocked-credentials-provi](./quick/261021-iz1-add-file-based-clocked-credentials-provi/) |
