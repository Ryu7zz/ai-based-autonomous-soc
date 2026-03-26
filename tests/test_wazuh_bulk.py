from pathlib import Path

import app.service as service_module
from app.service import DetectionService


def _build_alert(index: int, high_rule: bool) -> dict[str, object]:
    level = 12 if high_rule else 2
    return {
        "timestamp": "2026-03-25T10:21:00Z",
        "rule": {
            "level": level,
            "description": "Multiple authentication failures" if high_rule else "Routine access",
            "firedtimes": 4,
            "groups": ["authentication_failed"] if high_rule else ["web"],
        },
        "agent": {"name": f"host-{index % 5}"},
        "data": {
            "srcip": "185.44.9.10" if high_rule else "10.0.0.5",
            "dstip": "10.0.0.15",
            "dstport": "22" if high_rule else "443",
            "proto": "tcp",
            "bytes": str(14000 + index),
            "packets": str(160 + (index % 40)),
            "duration": "12",
            "failed_attempts": "15" if high_rule else "0",
        },
    }


class FakeWazuhClient:
    def iter_alerts(self, max_items: int, batch_size: int = 5000, time_range: str = "30d"):
        for index in range(max_items):
            yield _build_alert(index=index, high_rule=(index % 2 == 0))


def test_analyze_wazuh_bulk_supports_100k_style_runs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(service_module, "WazuhClient", FakeWazuhClient)
    service = DetectionService(model_path=tmp_path / "demo-model.pkl")

    result = service.analyze_wazuh_bulk(
        target_count=1000,
        batch_size=250,
        time_range="30d",
        include_samples=True,
        sample_size=5,
    )

    assert result.requested_count == 1000
    assert result.analyzed_count == 1000
    assert result.label_counts
    assert result.severity_counts
    assert len(result.top_samples) == 5


def test_retrain_from_wazuh_uses_streamed_alerts(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(service_module, "WazuhClient", FakeWazuhClient)
    service = DetectionService(model_path=tmp_path / "wazuh-model.pkl")

    info = service.retrain_from_wazuh(limit=200, time_range="30d", seed=7)

    assert info.dataset_rows == 200
    assert set(info.classes) == {"Incident", "Normal"}
