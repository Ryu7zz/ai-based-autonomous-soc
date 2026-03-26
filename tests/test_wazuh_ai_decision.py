from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app, get_service
from app.service import DetectionService


def test_wazuh_ai_decision_returns_block_request_for_high_risk_event(tmp_path: Path) -> None:
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
        response = client.post("/api/wazuh/ai/decision?include_normalized=true", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "decision_ready"
        assert data["should_block"] is True
        assert data["source_ip"] == "185.44.9.10"
        assert data["wazuh_block_request"]["command"] == "firewall-drop"
        assert data["wazuh_block_request"]["srcip"] == "185.44.9.10"
        assert data["normalized_event"]["srcip"] == "185.44.9.10"
    finally:
        app.dependency_overrides.clear()


def test_wazuh_ai_decision_returns_allow_for_low_risk_event(tmp_path: Path) -> None:
    service = DetectionService(
        model_path=tmp_path / "demo-model.pkl",
        webhook_db_path=tmp_path / "webhook.db",
    )
    app.dependency_overrides[get_service] = lambda: service
    client = TestClient(app)

    payload = {
        "timestamp": "2026-03-25T10:30:00Z",
        "rule": {
            "level": 2,
            "description": "Routine web request",
            "firedtimes": 1,
            "groups": ["web"],
        },
        "data": {
            "srcip": "10.10.1.5",
            "dstip": "10.0.0.15",
            "dstport": "443",
            "proto": "tcp",
            "bytes": "2048",
            "packets": "20",
            "duration": "8",
            "failed_attempts": "0",
        },
    }

    try:
        response = client.post("/api/wazuh/ai/decision", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "decision_ready"
        assert data["should_block"] is False
        assert data["wazuh_block_request"] is None
    finally:
        app.dependency_overrides.clear()
