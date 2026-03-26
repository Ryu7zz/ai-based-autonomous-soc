from pathlib import Path

import app.service as service_module
from app.service import DetectionService


def test_service_flags_bruteforce_event(tmp_path: Path) -> None:
    service = DetectionService(model_path=tmp_path / "demo-model.pkl")
    event = {
        "srcip": "185.44.9.10",
        "destip": "10.0.0.15",
        "destport": 22,
        "protocol": "tcp",
        "message": "Brute force login failed against ssh service",
        "rule": {
            "level": 12,
            "description": "Multiple authentication failures detected on SSH",
        },
        "network": {
            "bytes": 12400,
            "packets": 155,
            "duration": 18,
        },
        "auth": {
            "failures": 21,
        },
        "labels": {
            "same_source_hits": 9,
        },
        "agent": {
            "name": "linux-web-01",
        },
    }

    result = service.analyze_event(event)

    assert result.label == "Brute Force"
    assert result.risk_score >= 70
    assert result.active_response_enabled is True
    assert "iptables" in (result.response_command or "")


def test_service_identifies_normal_event(tmp_path: Path) -> None:
    service = DetectionService(model_path=tmp_path / "demo-model.pkl")
    event = {
        "srcip": "10.10.2.15",
        "destip": "10.10.0.25",
        "destport": 443,
        "protocol": "tcp",
        "message": "Routine HTTPS request",
        "rule": {
            "level": 2,
            "description": "Normal dashboard access",
        },
        "network": {
            "bytes": 16240,
            "packets": 60,
            "duration": 210,
        },
        "auth": {
            "failures": 0,
        },
    }

    result = service.analyze_event(event)

    assert result.label == "Normal"
    assert result.active_response_enabled is False


def test_service_analyzes_raw_wazuh_payload(tmp_path: Path) -> None:
    service = DetectionService(model_path=tmp_path / "demo-model.pkl")
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

    result, normalized = service.analyze_raw_event(payload=payload, source="wazuh")

    assert normalized["srcip"] == "185.44.9.10"
    assert result.label == "Brute Force"
    assert result.active_response_enabled is True


class _FakeDecisionBoardClient:
    def iter_alerts(self, max_items: int, batch_size: int = 5000, time_range: str = "24h"):
        for index in range(max_items):
            if index == 0:
                yield {
                    "id": "alert-1",
                    "timestamp": "2026-03-26T10:53:51.436+0800",
                    "rule": {
                        "id": "100501",
                        "level": 12,
                        "description": "Custom brute-force threshold exceeded",
                        "groups": ["authentication_failed"],
                    },
                    "full_log": "Failed password for invalid user test from 185.44.9.10 port 801 ssh2",
                    "data": {
                        "srcip": "185.44.9.10",
                        "dstip": "10.0.0.15",
                        "dstport": "22",
                        "proto": "tcp",
                        "failed_attempts": "22",
                    },
                }
            elif index == 1:
                yield {
                    "id": "alert-2",
                    "timestamp": "2026-03-26T10:53:51.503+0800",
                    "rule": {
                        "id": "651",
                        "level": 3,
                        "description": "Host Blocked by firewall-drop Active Response",
                        "groups": ["active_response"],
                    },
                    "full_log": "active-response/bin/firewall-drop add srcip 185.44.9.10",
                    "data": {
                        "srcip": "185.44.9.10",
                    },
                }
            else:
                yield {
                    "id": "alert-3",
                    "timestamp": "2026-03-26T10:56:00.000+0800",
                    "rule": {
                        "id": "19008",
                        "level": 2,
                        "description": "Routine service message",
                        "groups": ["syslog"],
                    },
                    "full_log": "Routine service message",
                    "data": {
                        "srcip": "10.10.10.10",
                        "dstip": "10.0.0.15",
                        "dstport": "443",
                        "proto": "tcp",
                    },
                }


def test_wazuh_decision_board_correlates_block_evidence(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(service_module, "WazuhClient", _FakeDecisionBoardClient)
    service = DetectionService(model_path=tmp_path / "demo-model.pkl")

    board = service.wazuh_decision_board(limit=3, time_range="24h")

    assert board.analyzed_count == 3
    assert board.blocked_count >= 1
    assert board.monitor_count >= 1
    assert any(row.source_ip == "185.44.9.10" and row.blocked_by_wazuh for row in board.rows)
