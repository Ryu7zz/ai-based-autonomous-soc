from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app, get_service
from app.service import DetectionService


class _FakeDecisionBoardService(DetectionService):
    def wazuh_decision_board(self, limit: int = 200, time_range: str = "24h"):
        return {
            "requested_count": limit,
            "analyzed_count": 1,
            "blocked_count": 1,
            "should_block_count": 0,
            "monitor_count": 0,
            "rows": [
                {
                    "timestamp": "2026-03-26T10:53:51.436+0800",
                    "event_id": "alert-1",
                    "wazuh_rule_id": "100501",
                    "wazuh_rule_description": "Custom brute-force threshold exceeded",
                    "source_ip": "185.44.9.10",
                    "destination_ip": "10.0.0.15",
                    "destination_port": "22",
                    "model_label": "Brute Force",
                    "model_confidence": 0.96,
                    "risk_score": 91.2,
                    "severity": "critical",
                    "decision": "blocked",
                    "decision_reason": "Wazuh active response already blocked this source IP.",
                    "response_command": "iptables -A INPUT -s 185.44.9.10 -j DROP",
                    "blocked_by_wazuh": True,
                    "block_event_id": "ar-1",
                    "block_event_timestamp": "2026-03-26T10:53:51.503+0800",
                    "block_event_rule_id": "651",
                    "summary": "Likely brute force attempt",
                    "full_log": "Failed password ...",
                }
            ],
        }


def test_wazuh_decision_board_endpoint() -> None:
    service = _FakeDecisionBoardService(model_path=Path("/tmp/demo-model.pkl"))
    app.dependency_overrides[get_service] = lambda: service
    client = TestClient(app)

    try:
        response = client.get("/api/wazuh/decision-board?limit=50&time_range=24h")
        assert response.status_code == 200
        payload = response.json()
        assert payload["requested_count"] == 50
        assert payload["blocked_count"] == 1
        assert payload["rows"][0]["decision"] == "blocked"
        assert payload["rows"][0]["source_ip"] == "185.44.9.10"
    finally:
        app.dependency_overrides.clear()