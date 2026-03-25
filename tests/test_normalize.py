from app.normalize import normalize_security_event


def test_normalize_wazuh_payload() -> None:
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

    normalized = normalize_security_event(payload, source="wazuh")

    assert normalized["srcip"] == "185.44.9.10"
    assert normalized["destip"] == "10.0.0.15"
    assert normalized["destport"] == "22"
    assert normalized["protocol"] == "tcp"
    assert normalized["rule"]["level"] == 12
    assert normalized["auth"]["failures"] == "22"
    assert normalized["labels"]["same_source_hits"] == 14


def test_normalize_ecs_payload() -> None:
    payload = {
        "@timestamp": "2026-03-25T10:33:00Z",
        "message": "Traffic spike may indicate DDoS flood",
        "source": {"ip": "198.51.100.44"},
        "destination": {"ip": "10.0.0.80", "port": 443},
        "network": {"transport": "tcp", "bytes": 920000, "packets": 8600},
        "event": {
            "category": ["network", "denial_of_service"],
            "dataset": "suricata.alert",
            "duration": 21000000000,
            "severity": 13,
        },
    }

    normalized = normalize_security_event(payload, source="ecs")

    assert normalized["srcip"] == "198.51.100.44"
    assert normalized["destip"] == "10.0.0.80"
    assert normalized["destport"] == 443
    assert normalized["protocol"] == "tcp"
    assert normalized["rule"]["level"] == 13
    assert normalized["network"]["duration"] == 21.0

