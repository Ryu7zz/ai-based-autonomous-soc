from app.features import event_to_features


def test_event_to_features_extracts_security_signals() -> None:
    event = {
        "srcip": "185.44.9.10",
        "destip": "10.0.0.15",
        "destport": 22,
        "protocol": "tcp",
        "message": "Brute force login failed against ssh service",
        "rule": {
            "level": 12,
            "description": "Multiple authentication failures detected on SSH",
            "firedtimes": 11,
        },
        "network": {
            "bytes": 12400,
            "packets": 155,
            "duration": 18,
        },
        "auth": {
            "failures": 21,
        },
    }

    features = event_to_features(event)

    assert features["rule_level"] == 12
    assert features["is_ssh_port"] == 1
    assert features["auth_failures"] == 21
    assert features["bruteforce_hint"] >= 2
    assert features["src_is_private"] == 0
    assert features["dest_is_private"] == 1

