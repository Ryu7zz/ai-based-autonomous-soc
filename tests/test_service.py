from pathlib import Path

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
