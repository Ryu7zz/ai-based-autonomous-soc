from __future__ import annotations

import app.wazuh_client as wazuh_client_module
from app.wazuh_client import WazuhClient


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_wazuh_client_uses_bearer_token_without_basic_auth(monkeypatch) -> None:
    captured = {}

    def fake_request(method, url, params=None, auth=None, headers=None, verify=None, timeout=None):
        captured["method"] = method
        captured["url"] = url
        captured["auth"] = auth
        captured["headers"] = headers
        return _FakeResponse(payload={"data": {"affected_items": [{"id": "a1"}]}})

    monkeypatch.setattr(wazuh_client_module.requests, "request", fake_request)

    client = WazuhClient(
        url="https://example-wazuh:55000",
        token="Bearer token-abc-123",
        password="",
    )

    items = client.get_alerts_page(limit=1, offset=0)

    assert len(items) == 1
    assert captured["auth"] is None
    assert captured["headers"] == {"Authorization": "Bearer token-abc-123"}


def test_wazuh_client_reads_alerts_from_file_mode(tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    alerts_file.write_text(
        "\n".join(
            [
                '{"id":"a1","timestamp":"2026-03-26T10:00:00+00:00","rule":{"id":"100"}}',
                '{"id":"a2","timestamp":"2026-03-26T10:10:00+00:00","rule":{"id":"101"}}',
            ]
        ),
        encoding="utf-8",
    )

    client = WazuhClient(source_mode="file", alerts_file=alerts_file, password="")
    items = list(client.iter_alerts(max_items=2, time_range="30d"))

    assert len(items) == 2
    assert items[0]["id"] == "a2"
    assert items[1]["id"] == "a1"


def test_wazuh_client_falls_back_to_file_when_api_fails(monkeypatch, tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    alerts_file.write_text(
        '{"id":"fallback-1","timestamp":"2026-03-26T10:10:00+00:00","rule":{"id":"100501"}}\n',
        encoding="utf-8",
    )

    def fake_request(*args, **kwargs):
        raise RuntimeError("api unavailable")

    monkeypatch.setattr(wazuh_client_module.requests, "request", fake_request)

    client = WazuhClient(
        source_mode="auto",
        alerts_file=alerts_file,
        password="",
        token="",
    )

    items = list(client.iter_alerts(max_items=1, time_range="30d"))
    assert len(items) == 1
    assert items[0]["id"] == "fallback-1"
