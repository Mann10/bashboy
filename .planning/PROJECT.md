# BashBoy

## What This Is

A shell-command safety gate for AI coding agents. BashBoy inspects a command before
it runs, short-circuits the obvious cases locally, and asks a hosted classifier model
(Clocked) about anything ambiguous. It ships as a Python package runnable with `uv`/`uvx`,
with integrations for Claude Code (PreToolUse hook) and OpenCode (plugin).

## Core Value

An agent should not be able to run a destructive shell command just because a human
was not watching. The gate must add safety without granting extra permissions, and it
must stay fast enough that it never becomes the reason someone disables it.

## Requirements

### Validated

(None yet)

### Active

- Package runs from `uvx` with no runtime dependencies beyond the standard library.
- Local denylist/allowlist fast paths resolve obvious commands with zero model latency.
- Ambiguous commands are classified by the Clocked API; failures fail closed.
- Claude Code PreToolUse hook integration (deny only, never auto-approve).
- OpenCode V2 plugin integration (V1 fallback), deny by throwing.
- Installer writes host config without clobbering unrelated settings.

### Out of Scope

- Granting/auto-approving commands. BashBoy only narrows what may run.
- A hosted service or dashboard. Local CLI only for v1.
- Windows PowerShell command parsing parity with bash (best-effort in v1).

## Key Decisions

- **Stdlib HTTP**: `urllib.request` instead of `httpx`/`requests` to keep hook startup fast.
- **Two-way verdict**: `allow` (no decision, host permissions still apply) or `deny`.
- **Fail closed**: provider error/timeout/malformed response denies the command.
- **Fast paths are structural**: the allowlist only matches a single simple command with
  no pipes, redirections, substitutions, or chaining.

## Context

Greenfield project. Host APIs:
- Claude Code: PreToolUse stdin JSON, `hookSpecificOutput.permissionDecision`.
- OpenCode V2: `ctx.tool.hook("execute.before", ...)`; V1: `tool.execute.before`.

## Evolution

This document evolves at phase transitions and milestone boundaries.
