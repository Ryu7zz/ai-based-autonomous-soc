from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app, get_service
from app.service import DetectionService


def test_wazuh_webhook_ingestion_and_history(tmp_path: Path) -> None:
    service = DetectionService(
        model_path=tmp_path / "demo-model.pkl",
        webhook_db_path=tmp_path / "webhook.db",
    )
    app.dependency_overrides[get_service] = lambda: service
    client = TestClient(app)

    payload = {
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

    try:
        ingest_response = client.post("/api/webhook/wazuh?include_normalized=true", json=payload)
        assert ingest_response.status_code == 200
        ingest_data = ingest_response.json()

        assert ingest_data["status"] == "processed"
        assert ingest_data["source"] == "wazuh"
        assert ingest_data["result"]["label"] == "Brute Force"
        assert ingest_data["normalized_event"]["srcip"] == "185.44.9.10"

        history_response = client.get("/api/webhook/events?limit=5")
        assert history_response.status_code == 200
        history = history_response.json()
        assert len(history) == 1
        assert history[0]["label"] == "Brute Force"
        assert history[0]["srcip"] == "185.44.9.10"

        ingestion_id = history[0]["ingestion_id"]
        detail_response = client.get(f"/api/webhook/events/{ingestion_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        assert detail["normalized_event"]["srcip"] == "185.44.9.10"
        assert detail["raw_payload"]["data"]["srcip"] == "185.44.9.10"
    finally:
        app.dependency_overrides.clear()
