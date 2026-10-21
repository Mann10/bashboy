"""Credential-file tests: precedence, permission policy, atomic writes, no leaks.

Every test is offline. POSIX mode assertions are skipped on Windows; the Windows
branch is exercised by monkeypatching the platform seam.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from bashboy import config, credentials
from bashboy.classify import classify_command

SENTINEL = "sk-bb-sentinel-DO-NOT-LEAK"
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")


def write_credential(path: Path, token: str = SENTINEL, *, overwrite: bool = True) -> Path:
    credentials.write_token(path, token, overwrite=overwrite)
    return path


def cfg_for(tmp_path, monkeypatch: pytest.MonkeyPatch, key_file: Path):
    monkeypatch.setenv("BASHBOY_API_KEY_FILE", str(key_file))
    return config.load_config(tmp_path / "absent.toml")


# --- resolution order -----------------------------------------------------


def test_env_var_wins_over_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = write_credential(tmp_path / "cred")
    monkeypatch.setenv("CLOCKED_API_KEY", "env-secret")
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    assert config.resolve_api_key(cfg) == ("env-secret", "env CLOCKED_API_KEY")


def test_file_used_when_env_absent(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = write_credential(tmp_path / "cred")
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    token, source = config.resolve_api_key(cfg)
    assert token == SENTINEL
    assert source == f"file {key_file} (owner-only)"
    assert config.api_key(cfg) == SENTINEL


def test_api_key_file_env_wins_over_toml(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    toml_file = write_credential(tmp_path / "from-toml", "toml-secret")
    env_file = write_credential(tmp_path / "from-env", "env-file-secret")
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(f'[provider]\napi_key_file = "{toml_file.as_posix()}"\n', encoding="utf-8")
    monkeypatch.setenv("BASHBOY_API_KEY_FILE", str(env_file))
    cfg = config.load_config(cfg_path)
    assert cfg.provider.api_key_file == env_file
    assert config.resolve_api_key(cfg)[0] == "env-file-secret"


def test_missing_file_means_no_key(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = cfg_for(tmp_path, monkeypatch, tmp_path / "does-not-exist")
    assert config.resolve_api_key(cfg) == (None, "none")
    assert config.api_key(cfg) is None


def test_empty_file_means_no_key(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text("", encoding="utf-8")
    if os.name != "nt":
        os.chmod(key_file, 0o600)
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    assert config.resolve_api_key(cfg) == (None, "none")


def test_whitespace_only_file_means_no_key(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text("  \n\t\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(key_file, 0o600)
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    assert config.resolve_api_key(cfg) == (None, "none")


def test_token_whitespace_is_stripped(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text(f"  {SENTINEL}\n\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(key_file, 0o600)
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    assert config.resolve_api_key(cfg)[0] == SENTINEL


# --- POSIX permission policy ---------------------------------------------


@POSIX_ONLY
def test_posix_world_readable_file_is_refused(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text(SENTINEL + "\n", encoding="utf-8")
    os.chmod(key_file, 0o644)
    with pytest.raises(credentials.CredentialPermissionError) as excinfo:
        credentials.read_token(key_file)
    message = str(excinfo.value)
    assert "chmod 600" in message
    assert str(key_file) in message
    assert SENTINEL not in message

    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    with pytest.raises(credentials.CredentialPermissionError):
        config.resolve_api_key(cfg)


@POSIX_ONLY
def test_posix_group_readable_file_is_refused(tmp_path) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text(SENTINEL + "\n", encoding="utf-8")
    os.chmod(key_file, 0o640)
    with pytest.raises(credentials.CredentialPermissionError):
        credentials.read_token(key_file)


@POSIX_ONLY
def test_posix_0600_file_is_accepted(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = write_credential(tmp_path / "cred")
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert credentials.read_token(key_file) == SENTINEL
    state = credentials.permissions(key_file)
    assert state.label == "owner-only"
    assert "0600" in state.detail


@POSIX_ONLY
def test_posix_insecure_state_is_reported(tmp_path) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text(SENTINEL + "\n", encoding="utf-8")
    os.chmod(key_file, 0o644)
    state = credentials.permissions(key_file)
    assert state.label == "insecure"
    assert "chmod 600" in state.detail


def test_classify_turns_permission_refusal_into_fail_closed(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission refusal only")
    key_file = tmp_path / "cred"
    key_file.write_text(SENTINEL + "\n", encoding="utf-8")
    os.chmod(key_file, 0o644)
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    result = classify_command("docker build .", cfg=cfg)
    assert result.decision == "deny"
    assert result.source == "fallback"
    assert "chmod 600" in result.reason
    assert SENTINEL not in result.reason


# --- Windows policy -------------------------------------------------------


def test_windows_extra_principals_are_reported_not_refused(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file = tmp_path / "cred"
    key_file.write_text(SENTINEL + "\n", encoding="utf-8")
    monkeypatch.setattr(credentials, "_is_windows", lambda: True)
    monkeypatch.setattr(
        credentials, "_windows_extra_principals", lambda path: ["BUILTIN\\Users"]
    )
    monkeypatch.setenv("BASHBOY_DEBUG", "1")

    # Warn-only: the token is still returned (D-04).
    assert credentials.read_token(key_file) == SENTINEL

    state = credentials.permissions(key_file, probe_acl=True)
    assert state.label == "extra-principals"
    assert "BUILTIN\\Users" in state.detail
    assert SENTINEL not in state.detail
    assert SENTINEL not in capsys.readouterr().err


def test_windows_hot_path_never_probes_the_acl(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`bashboy check` runs on every tool call: no subprocess may be spawned."""
    key_file = write_credential(tmp_path / "cred")

    def explode(path):
        raise AssertionError("ACL probe must not run on the hot path")

    monkeypatch.setattr(credentials, "_is_windows", lambda: True)
    monkeypatch.setattr(credentials, "_windows_extra_principals", explode)

    assert credentials.read_token(key_file) == SENTINEL
    assert credentials.permissions(key_file).label == "owner-only"


def test_windows_unverifiable_acl_is_reported(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = write_credential(tmp_path / "cred")
    monkeypatch.setattr(credentials, "_is_windows", lambda: True)
    monkeypatch.setattr(credentials, "_windows_extra_principals", lambda path: None)
    assert credentials.permissions(key_file, probe_acl=True).label == "unverified"


def test_missing_state(tmp_path) -> None:
    state = credentials.permissions(tmp_path / "absent")
    assert state.label == "missing"
    assert "does not exist" in state.detail


def test_windows_acl_parsing_skips_baseline_and_read_only(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    output = (
        f"{tmp_path}\\cred DOMAIN\\me:(F)\n"
        "    NT AUTHORITY\\SYSTEM:(I)(F)\n"
        "    BUILTIN\\Administrators:(I)(F)\n"
        "    CREATOR OWNER:(I)(F)\n"
        "    OWNER RIGHTS:(I)(F)\n"
        "    BUILTIN\\Users:(I)(R)\n"
        "    DOMAIN\\other:(I)(M)\n"
        "\nSuccessfully processed 1 files; Failed processing 0 files\n"
    )

    class Completed:
        returncode = 0
        stdout = output

    monkeypatch.setenv("USERNAME", "me")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Completed())
    assert credentials._windows_extra_principals(tmp_path / "cred") == ["DOMAIN\\other"]


def test_windows_acl_probe_failure_is_unverified(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    def explode(*args, **kwargs):
        raise OSError("icacls missing")

    monkeypatch.setattr(subprocess, "run", explode)
    assert credentials._windows_extra_principals(tmp_path / "cred") is None


# --- write / clear mechanics ---------------------------------------------


def test_write_token_creates_parent_and_contents(tmp_path) -> None:
    target = tmp_path / "nested" / ".bashboy" / "credentials"
    credentials.write_token(target, f"  {SENTINEL}  ")
    assert target.read_text(encoding="utf-8") == SENTINEL + "\n"


@POSIX_ONLY
def test_write_token_modes(tmp_path) -> None:
    target = tmp_path / "private" / "credentials"
    credentials.write_token(target, SENTINEL)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700


@POSIX_ONLY
def test_write_token_does_not_tighten_existing_directory(tmp_path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    os.chmod(parent, 0o755)
    credentials.write_token(parent / "credentials", SENTINEL)
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_write_token_refuses_existing_without_overwrite(tmp_path) -> None:
    target = write_credential(tmp_path / "cred")
    before = target.read_bytes()
    with pytest.raises(credentials.CredentialExistsError) as excinfo:
        credentials.write_token(target, "other-token")
    assert "--force" in str(excinfo.value)
    assert target.read_bytes() == before


def test_write_token_overwrite_replaces(tmp_path) -> None:
    target = write_credential(tmp_path / "cred")
    credentials.write_token(target, "other-token", overwrite=True)
    assert target.read_text(encoding="utf-8") == "other-token\n"


@pytest.mark.parametrize("token", ["", "   ", "a\nb", "a\rb"])
def test_write_token_rejects_invalid_tokens(tmp_path, token: str) -> None:
    with pytest.raises(credentials.CredentialError):
        credentials.write_token(tmp_path / "cred", token)
    assert not (tmp_path / "cred").exists()


def test_clear_token(tmp_path) -> None:
    target = write_credential(tmp_path / "cred")
    assert credentials.clear_token(target) is True
    assert not target.exists()
    assert credentials.clear_token(target) is False


def test_read_token_ignores_directories(tmp_path) -> None:
    assert credentials.read_token(tmp_path) is None


# --- error message quality ------------------------------------------------


def test_no_key_uses_local_rules_and_hints_at_auth_set(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = cfg_for(tmp_path, monkeypatch, tmp_path / "absent")
    result = classify_command("docker build .", cfg=cfg)
    assert result.decision == "allow"
    assert result.source == "local-only"
    assert "bashboy auth set" in result.reason


# --- no leaks -------------------------------------------------------------


def test_sentinel_never_appears_in_labels_or_states(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file = write_credential(tmp_path / "cred")
    cfg = cfg_for(tmp_path, monkeypatch, key_file)
    token, source = config.resolve_api_key(cfg)
    assert token == SENTINEL
    assert SENTINEL not in source
    assert SENTINEL not in repr(credentials.permissions(key_file))
    assert SENTINEL not in repr(credentials.permissions(tmp_path / "absent"))

    with pytest.raises(credentials.CredentialExistsError) as excinfo:
        credentials.write_token(key_file, SENTINEL)
    assert SENTINEL not in str(excinfo.value)

    captured = capsys.readouterr()
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err
