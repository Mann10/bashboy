"""Layered policy tests: parsing, precedence, tighten-only, and org flags."""

from __future__ import annotations

from pathlib import Path

import pytest

from bashboy.policy import (
    MAX_COMMAND_LENGTH,
    PolicyError,
    PolicyHit,
    evaluate_policy,
    load_policy,
    policy_paths,
    project_policy_path,
)

DENY_PROD = """\
version = 1

[[rule]]
id = "no-prod-db"
action = "deny"
match = '(?i)\\bpsql\\b.*\\bprod'
reason = "Production database access is prohibited"
"""

ALLOW_RM = """\
version = 1

[[rule]]
id = "allow-sandbox-rm"
action = "allow"
match = '^rm -rf /tmp/sandbox'
reason = "sandbox cleanup is allowed"
"""


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def use_explicit(monkeypatch: pytest.MonkeyPatch, path: Path) -> Path:
    monkeypatch.setenv("BASHBOY_POLICY", str(path))
    return path


def test_explicit_policy_deny(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = use_explicit(monkeypatch, write(tmp_path / "policy.toml", DENY_PROD))
    loaded = load_policy(str(tmp_path))
    assert [rule.id for rule in loaded.rules] == ["no-prod-db"]
    assert loaded.sources == (("explicit", path, True),)

    hit = evaluate_policy(loaded, "psql -h prod-db", str(tmp_path))
    assert hit == PolicyHit(
        "deny",
        "no-prod-db",
        "Production database access is prohibited",
        "explicit",
    )


def test_explicit_policy_allow(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", ALLOW_RM))
    loaded = load_policy(str(tmp_path))
    hit = evaluate_policy(loaded, "rm -rf /tmp/sandbox/build", str(tmp_path))
    assert hit == PolicyHit(
        "allow", "allow-sandbox-rm", "sandbox cleanup is allowed", "explicit"
    )
    assert evaluate_policy(loaded, "rm -rf /tmp/other", str(tmp_path)) is None


def test_first_matching_rule_wins(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = """\
version = 1

[[rule]]
id = "first"
action = "deny"
contains = "docker"
reason = "first"

[[rule]]
id = "second"
action = "allow"
contains = "docker"
reason = "second"
"""
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", text))
    hit = evaluate_policy(load_policy(str(tmp_path)), "docker build .")
    assert hit is not None
    assert hit.rule_id == "first"
    assert hit.decision == "deny"


def test_matching_applies_to_command_fragments(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", DENY_PROD))
    loaded = load_policy(str(tmp_path))
    assert evaluate_policy(loaded, "ls && psql prod", str(tmp_path)) is not None
    assert evaluate_policy(loaded, "echo 'psql prod'", str(tmp_path)) is not None


def test_cwd_glob_filters_a_rule(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    text = f"""\
version = 1

[[rule]]
id = "no-kubectl-delete"
action = "deny"
contains = "kubectl delete"
cwd = "{work.as_posix()}/**"
reason = "forbidden here"
"""
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", text))
    loaded = load_policy(str(tmp_path))

    assert evaluate_policy(loaded, "kubectl delete pod x", str(work / "app")) is not None
    assert evaluate_policy(loaded, "kubectl delete pod x", str(tmp_path / "other")) is None


def test_cwd_matching_is_case_insensitive(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "Work"
    text = f"""\
version = 1

[[rule]]
id = "scoped"
action = "deny"
contains = "danger"
cwd = "{work.as_posix().lower()}/**"
reason = "scoped"
"""
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", text))
    loaded = load_policy(str(tmp_path))
    assert evaluate_policy(loaded, "danger", str(work / "Sub")) is not None


def test_project_allow_is_ignored(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = write(tmp_path / "project.toml", ALLOW_RM)
    monkeypatch.setenv("BASHBOY_POLICY_PROJECT", str(project))

    loaded = load_policy(str(tmp_path))
    rule = loaded.rules[0]
    assert rule.ignored is not None
    assert "tighten-only" in rule.ignored
    assert evaluate_policy(loaded, "rm -rf /tmp/sandbox/x") is None


def test_project_deny_is_enforced(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = """\
version = 1

[[rule]]
id = "no-force-push"
action = "deny"
contains = "git push --force"
reason = "Force pushes are forbidden in this repo"
"""
    monkeypatch.setenv(
        "BASHBOY_POLICY_PROJECT", str(write(tmp_path / "project.toml", text))
    )
    loaded = load_policy(str(tmp_path))
    hit = evaluate_policy(loaded, "git push --force origin main")
    assert hit is not None
    assert hit.rule_id == "no-force-push"


def test_org_immutable_ignores_user_and_project_allow(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    org = write(
        tmp_path / "org.toml",
        "version = 1\n\n[policy]\nimmutable = true\n",
    )
    user = write(tmp_path / "user.toml", ALLOW_RM)
    project = write(tmp_path / "project.toml", ALLOW_RM)
    monkeypatch.setenv("BASHBOY_POLICY_ORG", str(org))
    monkeypatch.setenv("BASHBOY_POLICY_USER", str(user))
    monkeypatch.setenv("BASHBOY_POLICY_PROJECT", str(project))

    loaded = load_policy(str(tmp_path))
    allow_rules = [rule for rule in loaded.rules if rule.action == "allow"]
    assert allow_rules
    assert all(rule.ignored is not None for rule in allow_rules)
    assert evaluate_policy(loaded, "rm -rf /tmp/sandbox/x") is None


def test_org_deny_beats_user_allow(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    org_text = """\
version = 1

[[rule]]
id = "org-no-prod"
action = "deny"
contains = "prod"
reason = "org says no"
"""
    user_text = """\
version = 1

[[rule]]
id = "user-allow-prod"
action = "allow"
contains = "prod"
reason = "user says yes"
"""
    monkeypatch.setenv(
        "BASHBOY_POLICY_ORG", str(write(tmp_path / "org.toml", org_text))
    )
    monkeypatch.setenv(
        "BASHBOY_POLICY_USER", str(write(tmp_path / "user.toml", user_text))
    )

    loaded = load_policy(str(tmp_path))
    hit = evaluate_policy(loaded, "psql prod")
    assert hit is not None
    assert hit.rule_id == "org-no-prod"
    assert hit.decision == "deny"


def test_user_allow_can_override_builtin_rules(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "BASHBOY_POLICY_USER", str(write(tmp_path / "user.toml", ALLOW_RM))
    )
    loaded = load_policy(str(tmp_path))
    hit = evaluate_policy(loaded, "rm -rf /tmp/sandbox/x")
    assert hit is not None
    assert hit.decision == "allow"
    assert hit.source == "user"


def test_explicit_policy_can_set_org_flags(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "version = 1\n\n[policy]\nrequire_key = true\ndisable_escape_hatch = true\n"
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", text))
    flags = load_policy(str(tmp_path)).flags
    assert flags.require_key is True
    assert flags.disable_escape_hatch is True
    assert flags.immutable is False


def test_missing_sources_are_reported_and_harmless(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaded = load_policy(str(tmp_path))
    assert loaded.rules == ()
    assert [source for source, _, exists in loaded.sources] == ["org", "user", "project"]
    assert all(not exists for _, _, exists in loaded.sources)
    assert evaluate_policy(loaded, "anything") is None


def test_policy_paths_explicit_replaces_discovery(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = use_explicit(monkeypatch, tmp_path / "explicit.toml")
    assert policy_paths(str(tmp_path)) == (("explicit", path),)


def test_project_policy_is_discovered_from_a_parent(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BASHBOY_POLICY_PROJECT")
    root = tmp_path / "repo"
    expected = write(root / ".bashboy" / "policy.toml", "version = 1\n")
    nested = root / "src" / "pkg"
    nested.mkdir(parents=True)
    assert project_policy_path(str(nested)) == expected


def test_command_too_long_is_denied(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_explicit(monkeypatch, write(tmp_path / "policy.toml", DENY_PROD))
    loaded = load_policy(str(tmp_path))
    hit = evaluate_policy(loaded, "x" * (MAX_COMMAND_LENGTH + 1))
    assert hit is not None
    assert hit.rule_id == "command-too-long"
    assert hit.decision == "deny"


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("version = 2\n", "'version' must be 1"),
        ("", "'version' must be 1"),
        ("version = 1\n\n[[rules]]\nid = 'x'\n", "unknown key"),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'block'\nmatch = 'x'\n",
            "'action' must be one of",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\n"
            "match = 'x'\ncontains = 'x'\n",
            "exactly one of",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\n",
            "exactly one of",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\nmatch = '['\n",
            "invalid regex",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\n"
            "match = 'x'\nextra = 1\n",
            "unknown key",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\n"
            "match = 'x'\n\n[[rule]]\nid = 'x'\naction = 'deny'\nmatch = 'y'\n",
            "duplicate rule id",
        ),
        (
            "version = 1\n\n[policy]\nimmutable = 'yes'\n",
            "must be true or false",
        ),
        (
            "version = 1\n\n[[rule]]\nid = ''\naction = 'deny'\nmatch = 'x'\n",
            "'id' must be a non-empty string",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\ncontains = ''\n",
            "'contains' must be a non-empty string",
        ),
        (
            "version = 1\n\n[[rule]]\nid = 'x'\naction = 'deny'\nmatch = 'x'\n"
            "reason = '   '\n",
            "'reason' must be a non-empty string",
        ),
    ],
)
def test_invalid_policies_fail_closed(
    tmp_path, monkeypatch: pytest.MonkeyPatch, text: str, needle: str
) -> None:
    use_explicit(monkeypatch, write(tmp_path / "bad.toml", text))
    with pytest.raises(PolicyError) as exc:
        load_policy(str(tmp_path))
    assert needle in str(exc.value)


def test_only_the_org_policy_may_set_flags(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "BASHBOY_POLICY_USER",
        str(
            write(
                tmp_path / "user.toml",
                "version = 1\n\n[policy]\nrequire_key = true\n",
            )
        ),
    )
    with pytest.raises(PolicyError) as exc:
        load_policy(str(tmp_path))
    assert "only allowed in the org policy" in str(exc.value)


def test_missing_explicit_policy_is_an_error(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY", str(tmp_path / "missing.toml"))
    with pytest.raises(PolicyError) as exc:
        load_policy(str(tmp_path))
    assert "does not exist" in str(exc.value)


def test_non_utf8_policy_is_an_error(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bad.toml"
    path.write_bytes(b"\xff\xfe")
    use_explicit(monkeypatch, path)
    with pytest.raises(PolicyError):
        load_policy(str(tmp_path))
