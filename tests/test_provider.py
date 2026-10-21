"""Provider tests. A fake transport records calls; nothing touches the network."""

from __future__ import annotations

import json
import socket
import uuid

import pytest

from bashboy import provider
from bashboy.config import ProviderConfig


class FakeTransport:
    def __init__(self, status: int = 200, body: bytes = b'{"verdict":"allow"}', exc=None) -> None:
        self.status = status
        self.body = body
        self.exc = exc
        self.calls: list[tuple[str, bytes, dict[str, str], float]] = []

    def __call__(self, url, body, headers, timeout):
        self.calls.append((url, body, headers, timeout))
        if self.exc is not None:
            raise self.exc
        return self.status, self.body


def make_provider(transport, key: str | None = "k", timeout_ms: int = 4000) -> provider.Provider:
    cfg = ProviderConfig(timeout_ms=timeout_ms)
    return provider.Provider(cfg, transport=transport, key=key)


EXTRACT_CASES = [
    ({"verdict": "deny", "risk": "high", "reason": "r"}, "deny"),
    ({"fields": {"verdict": {"value": "deny"}}}, "deny"),
    ({"result": {"fields": {"verdict": {"text": "DENY"}}}}, "DENY"),
    (
        {"fields": [{"name": "verdict", "value": "deny"}, {"name": "reason", "value": "x"}]},
        "deny",
    ),
    ({"ok": True}, None),
    ({"data": {"output": {"verdict": {"label": "allow"}}}}, "allow"),
    ({"Verdict": "deny"}, "deny"),
]


@pytest.mark.parametrize(("payload", "expected"), EXTRACT_CASES)
def test_extract_field(payload, expected) -> None:
    assert provider.extract_field(payload, "verdict") == expected


def test_extract_field_handles_odd_input() -> None:
    assert provider.extract_field(None, "verdict") is None
    assert provider.extract_field("nope", "verdict") is None
    assert provider.extract_field([1, 2, 3], "verdict") is None
    assert provider.extract_field({"a": [{"b": [{"verdict": "deny"}]}]}, "verdict") == "deny"


def test_request_body_shape() -> None:
    body = provider.build_request_body("/tmp", "git push")
    assert body["text"] == "cwd: /tmp\ncommand: git push"
    instructions = body["instructions"]
    assert isinstance(instructions, str)
    assert "deny" in instructions
    assert "exfiltrate" in instructions
    assert "remote content" in instructions
    fields = body["fields"]
    assert fields["verdict"]["options"] == ["allow", "deny"]
    assert fields["risk"]["levels"] == ["low", "medium", "high", "critical"]
    assert fields["reason"]["max_tokens"] == 80


def test_request_headers_and_timeout() -> None:
    transport = FakeTransport()
    p = make_provider(transport, key="k", timeout_ms=4000)
    p.classify("/tmp", "git push")

    url, raw_body, headers, timeout = transport.calls[0]
    assert url == "https://clocked.rezolve.ai/clocked/fill"
    assert headers["Authorization"] == "Bearer k"
    assert headers["Content-Type"] == "application/json"
    assert uuid.UUID(headers["Idempotency-Key"]).version == 4
    assert timeout == 4.0
    decoded = json.loads(raw_body.decode("utf-8"))
    assert decoded["text"] == "cwd: /tmp\ncommand: git push"


def test_no_api_key_never_calls_transport() -> None:
    transport = FakeTransport()
    p = make_provider(transport, key=None)
    with pytest.raises(provider.ProviderError) as excinfo:
        p.classify("/tmp", "ls")
    assert "CLOCKED_API_KEY" in str(excinfo.value)
    assert transport.calls == []


def test_blank_api_key_is_rejected() -> None:
    transport = FakeTransport()
    p = make_provider(transport, key="   ")
    with pytest.raises(provider.ProviderError):
        p.classify("/tmp", "ls")
    assert transport.calls == []


def test_transport_timeout_maps_to_provider_timeout() -> None:
    transport = FakeTransport(exc=socket.timeout("timed out"))
    p = make_provider(transport)
    with pytest.raises(provider.ProviderTimeout):
        p.classify("/tmp", "ls")


def test_transport_oserror_maps_to_provider_error() -> None:
    transport = FakeTransport(exc=OSError("connection refused"))
    p = make_provider(transport)
    with pytest.raises(provider.ProviderError) as excinfo:
        p.classify("/tmp", "ls")
    assert not isinstance(excinfo.value, provider.ProviderTimeout)


def test_http_error_status_maps_to_provider_error() -> None:
    transport = FakeTransport(status=500, body=b"{}")
    p = make_provider(transport)
    with pytest.raises(provider.ProviderError) as excinfo:
        p.classify("/tmp", "ls")
    assert "500" in str(excinfo.value)


def test_non_json_body_is_malformed() -> None:
    transport = FakeTransport(body=b"<html>oops</html>")
    p = make_provider(transport)
    with pytest.raises(provider.ProviderMalformed):
        p.classify("/tmp", "ls")


@pytest.mark.parametrize(
    "payload",
    [
        {"verdict": "maybe"},
        {"verdict": ""},
        {"verdict": None},
        {"ok": True},
        {"verdict": {"unexpected": "shape"}},
    ],
)
def test_unrecognized_verdict_is_malformed(payload) -> None:
    transport = FakeTransport(body=json.dumps(payload).encode("utf-8"))
    p = make_provider(transport)
    with pytest.raises(provider.ProviderMalformed):
        p.classify("/tmp", "ls")


def test_verdict_is_normalized() -> None:
    transport = FakeTransport(body=b'{"verdict":"DENY","reason":"dangerous"}')
    p = make_provider(transport)
    verdict = p.classify("/tmp", "ls")
    assert verdict.decision == "deny"
    assert verdict.reason == "dangerous"


def test_risk_and_default_reason() -> None:
    transport = FakeTransport(body=b'{"fields":{"verdict":{"value":"allow"}}}')
    p = make_provider(transport)
    verdict = p.classify("/tmp", "ls")
    assert verdict.decision == "allow"
    assert verdict.risk is None
    assert verdict.reason == "model verdict"


def test_urllib_transport_wraps_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args, **kwargs):
        raise provider.urllib.error.HTTPError("http://x/fill", 503, "unavailable", {}, None)

    monkeypatch.setattr(provider.urllib.request, "urlopen", boom)
    with pytest.raises(provider.ProviderError) as excinfo:
        provider.urllib_transport("http://x/fill", b"{}", {}, 1.0)
    assert "503" in str(excinfo.value)


def test_urllib_transport_wraps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args, **kwargs):
        raise provider.urllib.error.URLError(socket.timeout("slow"))

    monkeypatch.setattr(provider.urllib.request, "urlopen", boom)
    with pytest.raises(provider.ProviderTimeout):
        provider.urllib_transport("http://x/fill", b"{}", {}, 1.0)


def test_urllib_transport_returns_status_and_body(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status = 200

        def read(self):
            return b'{"verdict":"allow"}'

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

    monkeypatch.setattr(provider.urllib.request, "urlopen", lambda *a, **k: FakeResponse())
    assert provider.urllib_transport("http://x/fill", b"{}", {}, 1.0) == (
        200,
        b'{"verdict":"allow"}',
    )

