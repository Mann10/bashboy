"""Tests for the structural allowlist and the hard denylist."""

from __future__ import annotations

import pytest

from bashboy import rules


ALLOWLIST_CASES = [
    ("ls -la", "ls"),
    ("pwd", "pwd"),
    ("git status", "git status"),
    ("git diff HEAD~1", "git diff"),
    ("git log --oneline -5", "git log"),
    ("git show HEAD", "git show"),
    ("git branch", "git branch"),
    ("uv --version", "uv --version"),
    ("python --version", "python --version"),
    ("node --version", "node --version"),
    ("find . -name '*.py'", "find"),
    ("cat pyproject.toml", "cat"),
    ("head -n 5 README.md", "head"),
    ("tail -n 5 README.md", "tail"),
    ("wc -l README.md", "wc"),
    ("grep -r bashboy src", "grep"),
    ("rg bashboy", "rg"),
    ("echo hello", "echo"),
    ("which python", "which"),
    ("whoami", "whoami"),
    ("date", "date"),
    ("cd /tmp", "cd"),
    ("cd", "cd"),
    ("   ls   ", "ls"),
]

NOT_ALLOWLISTED = [
    "ls | grep x",
    "ls; pwd",
    "echo $(whoami)",
    "ls > out.txt",
    "echo `date`",
    "ls && pwd",
    "cd /tmp && rm x",
    "ls\npwd",
    "ls || pwd",
    "ls & pwd",
    "cat < input.txt",
    "echo ${HOME}",
    "",
    "   ",
    "docker run --rm alpine sh",
    "uv run pytest",
    "python script.py",
    "node index.js",
    "git push",
    "git reset --hard",
    "git -c core.pager=cat push",
    "FOO=bar ls",
    "find . -delete",
    "find . -exec rm {} ;",
    "cd /tmp extra",
]

DENYLIST_HITS = [
    ("rm -rf /", "recursive delete of a protected path"),
    ("rm -fr ~", "recursive delete of a protected path"),
    ("rm -rf $HOME", "recursive delete of a protected path"),
    ("rm -rf /*", "recursive delete of a protected path"),
    ("sudo rm -rf /", "recursive delete of a protected path"),
    ("rm -rf /usr", "recursive delete of a protected path"),
    ("rm -r -f /", "recursive delete of a protected path"),
    ("rm -rf /etc/passwd", "recursive delete of a protected path"),
    ("RM -RF /VAR", "recursive delete of a protected path"),
    ("mkfs.ext4 /dev/sda1", "filesystem creation on a device"),
    ("mkfs /dev/sdb", "filesystem creation on a device"),
    ("fdisk /dev/sda", "disk partitioning"),
    ("parted /dev/sda", "disk partitioning"),
    ("diskpart", "disk partitioning"),
    ("format c:", "drive format"),
    ("dd if=/dev/zero of=/dev/sda", "raw write to a block device"),
    ("echo x > /dev/sda", "raw write to a block device"),
    ("shred -u /dev/sda", "shred of a block device"),
    (":(){ :|:& };:", "fork bomb"),
    ("chmod -R 777 /", "world-writable root"),
    ("chown -R root /", "ownership change on root"),
    ("shutdown -h now", "host power control"),
    ("reboot", "host power control"),
    ("halt", "host power control"),
    ("poweroff", "host power control"),
    ("Remove-Item -Recurse -Force C:\\", "recursive delete of a drive root"),
    ("ls; rm -rf /", "recursive delete of a protected path"),
    ("echo $(rm -rf /)", "recursive delete of a protected path"),
    ("echo $(echo $(rm -rf /))", "recursive delete of a protected path"),
    ("echo `rm -rf /`", "recursive delete of a protected path"),
    ("true && mkfs.ext4 /dev/sda", "filesystem creation on a device"),
    ("echo hi | rm -rf ~", "recursive delete of a protected path"),
    ("git clean -fdx /", "git clean at the filesystem root"),
    ("git clean -fd -- /", "git clean at the filesystem root"),
]

DENYLIST_MISSES = [
    "git reset --hard",
    "git status",
    "rm -rf ./build",
    "rm -rf node_modules",
    "ls -la",
    "git clean -fd",
    "docker run --rm alpine sh",
    "rm -rf build/",
    "rm file.txt",
    "mkdocs build",
    "dd if=in.img of=out.img",
    "",
]


@pytest.mark.parametrize(("command", "label"), ALLOWLIST_CASES)
def test_allowlist_hits(command: str, label: str) -> None:
    assert rules.check_allowlist(command) == label


@pytest.mark.parametrize("command", NOT_ALLOWLISTED)
def test_allowlist_misses(command: str) -> None:
    assert rules.check_allowlist(command) is None


@pytest.mark.parametrize(("command", "reason"), DENYLIST_HITS)
def test_denylist_hits(command: str, reason: str) -> None:
    hit = rules.check_denylist(command)
    assert hit is not None, command
    assert hit.reason == reason
    assert hit.pattern


@pytest.mark.parametrize("command", DENYLIST_MISSES)
def test_denylist_misses(command: str) -> None:
    assert rules.check_denylist(command) is None


@pytest.mark.parametrize("cwd", ["/", "C:\\", "c:/", None])
def test_wildcard_rm_denied_at_root(cwd: str | None) -> None:
    hit = rules.check_denylist("rm -rf *", cwd=cwd)
    assert hit is not None
    assert "wildcard" in hit.reason


@pytest.mark.parametrize("cwd", ["/home/me/proj", "C:\\personal\\BashBoy"])
def test_wildcard_rm_allowed_outside_root(cwd: str) -> None:
    assert rules.check_denylist("rm -rf *", cwd=cwd) is None


def test_segments_includes_raw_and_parts() -> None:
    parts = rules.segments("ls; rm -rf / && pwd")
    assert "ls; rm -rf / && pwd" in parts
    assert " rm -rf / " in parts
    assert " pwd" in parts


def test_segments_includes_nested_substitutions() -> None:
    parts = rules.segments("echo $(echo $(rm -rf /))")
    assert "rm -rf /" in parts


def test_segments_handles_unbalanced_substitution() -> None:
    parts = rules.segments("echo $(oops")
    assert "echo $(oops" in parts


def test_segments_depth_is_capped() -> None:
    command = "echo " + "$(" * 8 + "ls" + ")" * 8
    parts = rules.segments(command)
    assert parts
    assert len(parts) < 100


def test_denylist_ignores_non_string() -> None:
    assert rules.check_denylist(None) is None  # type: ignore[arg-type]


# --- quoted destructive targets -------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        'rm -rf "/"',
        "rm -rf '/usr'",
        'rm -rf "$HOME"',
        "rm -rf ~/",
        "rm -rf '/etc'",
        "rm -rf -- /",
        "rm -rf C:\\",
        'rm -rf "C:/"',
        "rm -rf /c/",
    ],
)
def test_quoted_protected_rm_targets_are_denied(command: str) -> None:
    hit = rules.check_denylist(command)
    assert hit is not None
    assert "protected path" in hit.reason


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ./build",
        "rm -rf node_modules",
        "rm -rf 'build dir'",
        "rm -rf C:\\Users\\me\\build",
    ],
)
def test_quoted_safe_rm_targets_are_not_denied(command: str) -> None:
    assert rules.check_denylist(command) is None


# --- .env protection ------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat .env",
        "cat ./.env",
        "head -n 5 .env.local",
        'cat "C:/proj/.env"',
        "grep -r API_KEY .env",
        "cp .env /tmp/leak",
        "echo SECRET=1 > .env",
        "echo SECRET=1 >> .env",
        "bash -c 'cat .env'",
        "sudo cat .env",
        "source .env",
        "sed -i s/a/b/ .env.production",
        "git diff .env",
        "git show HEAD:.env",
        "git add .env",
        "find . -name .env -exec cat {} \\;",
        "tar czf out.tgz .env",
    ],
)
def test_dotenv_access_is_denied(command: str) -> None:
    hit = rules.check_denylist(command)
    assert hit is not None
    assert ".env" in hit.reason


@pytest.mark.parametrize(
    "command",
    [
        "cat .env.example",
        "cat .env.sample",
        "cat .env.template",
        "echo FOO=1 > .env.example",
        'git commit -m "fix .env handling"',
        'echo "see .env for details"',
        "grep -r 'process.env' src",
        "ls -la",
        "find . -name .env -print",
    ],
)
def test_dotenv_false_positives_are_not_denied(command: str) -> None:
    assert rules.check_denylist(command) is None


def test_check_env_read_denies_dotenv_paths() -> None:
    assert rules.check_env_read(".env") is not None
    assert rules.check_env_read("C:/proj/.env.local") is not None
    assert rules.check_env_read("app\\.env.production") is not None


def test_check_env_read_allows_templates_and_other_files() -> None:
    assert rules.check_env_read(".env.example") is None
    assert rules.check_env_read("README.md") is None
    assert rules.check_env_read(None) is None
    assert rules.check_env_read("") is None


# --- catalog + basic Windows/env rules ------------------------------------


def test_rule_catalog_is_well_formed() -> None:
    ids = [rule.id for rule in rules.RULES]
    assert len(ids) == len(set(ids))
    assert {rule.category for rule in rules.RULES} == {"destructive", "env"}
    for rule in rules.RULES:
        assert rule.id and rule.reason and rule.example


def test_rule_catalog_matches_enforcement() -> None:
    catalog = {rule.pattern for rule in rules.RULES if rule.pattern is not None}
    assert catalog == {pattern for pattern, _ in rules.DENY_RULES}


@pytest.mark.parametrize(
    "command",
    [
        "del /s /q C:\\tmp",
        "rd /s /q build",
        "rmdir /s build",
        "find / -delete",
        "find / -exec rm -rf {} \\;",
        "wipefs -a /dev/sda",
        "blkdiscard /dev/nvme0n1",
    ],
)
def test_new_destructive_rules_are_denied(command: str) -> None:
    assert rules.check_denylist(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "printenv",
        "env",
        "set",
        "export -p",
        "cat /proc/self/environ",
        "Get-ChildItem Env:",
        "[Environment]::GetEnvironmentVariables()",
    ],
)
def test_environment_dumps_are_denied(command: str) -> None:
    hit = rules.check_denylist(command)
    assert hit is not None
    assert "environment dump" in hit.reason


@pytest.mark.parametrize(
    "command",
    [
        "printenv PATH",
        "env FOO=1 ls",
        "set -e",
        "Get-ChildItem .",
        "del file.txt",
        "find . -delete",
    ],
)
def test_environment_and_windows_false_positives_are_allowed(command: str) -> None:
    assert rules.check_denylist(command) is None
