from pathlib import Path

from app.service import DetectionService


def _sample_wazuh_payload() -> dict:
    return {
        "timestamp": "2026-03-25T10:21:00Z",
        "rule": {
            "level": 12,
            "description": "Multiple authentication failures detected on sshd",
            "firedtimes": 14,
            "groups": ["authentication_failed", "sshd"],
        },
        "agent": {"name": "linux-web-01"},
        "data": {
            "srcip": "185.44.9.10",
            "dstip": "10.0.0.15",
            "dstport": "22",
            "proto": "tcp",
            "bytes": "15422",
            "packets": "172",
            "duration": "20",
            "failed_attempts": "22",
        },
    }


def test_webhook_events_persist_between_service_instances(tmp_path: Path) -> None:
    model_path = tmp_path / "demo-model.pkl"
    db_path = tmp_path / "webhook.db"
    payload = _sample_wazuh_payload()

    writer = DetectionService(model_path=model_path, webhook_db_path=db_path)
    _, _, ingestion_id, _ = writer.ingest_webhook_event(payload=payload, source="wazuh")

    reader = DetectionService(model_path=model_path, webhook_db_path=db_path)
    history = reader.recent_webhook_events(limit=10)
    assert len(history) == 1
    assert history[0].ingestion_id == ingestion_id
    assert history[0].srcip == "185.44.9.10"

    detail = reader.webhook_event_by_ingestion_id(ingestion_id)
    assert detail is not None
    assert detail.normalized_event["srcip"] == "185.44.9.10"
    assert detail.raw_payload["data"]["dstport"] == "22"
    assert detail.result.label == "Brute Force"

