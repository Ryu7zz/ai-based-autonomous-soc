from __future__ import annotations

from typing import Any, Mapping


def _nested(data: Mapping[str, Any], *paths: tuple[str, ...] | str) -> Any:
    for path in paths:
        keys = (path,) if isinstance(path, str) else path
        current: Any = data
        for key in keys:
            if not isinstance(current, Mapping) or key not in current:
                break
            current = current[key]
        else:
            return current
    return None


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return default
        try:
            return float(text)
        except ValueError:
            return default
    return default


def _normalize_duration(value: Any) -> float:
    raw = _to_float(value, default=0.0)
    if raw <= 0:
        return 0.0
    if raw > 100_000_000:
        return raw / 1_000_000_000
    if raw > 100_000:
        return raw / 1_000_000
    return raw


def _normalize_wazuh(payload: Mapping[str, Any]) -> dict[str, Any]:
    data = payload.get("data", {})
    if not isinstance(data, Mapping):
        data = {}

    rule = payload.get("rule", {})
    if not isinstance(rule, Mapping):
        rule = {}

    groups = rule.get("groups")
    attack_type = groups if isinstance(groups, str) else ", ".join(groups or [])
    srcip = _first_non_empty(
        payload.get("srcip"),
        _nested(payload, ("source", "ip")),
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
    )
    destip = _first_non_empty(
        payload.get("destip"),
        payload.get("dstip"),
        _nested(payload, ("destination", "ip")),
        data.get("destip"),
        data.get("dstip"),
        data.get("dest_ip"),
        data.get("dst_ip"),
    )
    destport = _first_non_empty(
        payload.get("destport"),
        payload.get("dstport"),
        _nested(payload, ("destination", "port")),
        data.get("destport"),
        data.get("dstport"),
        data.get("dest_port"),
        data.get("dst_port"),
    )
    protocol = _first_non_empty(
        payload.get("protocol"),
        data.get("protocol"),
        data.get("proto"),
        _nested(payload, ("network", "protocol")),
        _nested(payload, ("network", "transport")),
    )

    total_bytes = _first_non_empty(
        _nested(payload, ("network", "bytes")),
        data.get("bytes"),
        data.get("size"),
    )
    if total_bytes is None:
        src_bytes = _to_float(data.get("srcbytes"), default=0.0)
        dst_bytes = _to_float(data.get("dstbytes"), default=0.0)
        if src_bytes or dst_bytes:
            total_bytes = src_bytes + dst_bytes

    auth_failures = _first_non_empty(
        _nested(payload, ("auth", "failures")),
        data.get("failed_attempts"),
        data.get("failures"),
        data.get("failed_logins"),
        rule.get("firedtimes"),
    )
    same_source_hits = _first_non_empty(
        _nested(payload, ("labels", "same_source_hits")),
        data.get("same_source_hits"),
        rule.get("firedtimes"),
    )

    normalized = {
        "timestamp": payload.get("timestamp"),
        "srcip": srcip,
        "destip": destip,
        "destport": destport,
        "protocol": str(protocol).lower() if protocol is not None else None,
        "message": _first_non_empty(
            payload.get("message"),
            payload.get("full_log"),
            rule.get("description"),
        ),
        "action": _first_non_empty(payload.get("action"), data.get("action")),
        "attack_type": _first_non_empty(
            payload.get("attack_type"),
            data.get("attack_type"),
            attack_type,
        ),
        "rule": {
            "level": _first_non_empty(rule.get("level"), _nested(payload, ("event", "severity"))),
            "description": rule.get("description"),
            "firedtimes": rule.get("firedtimes"),
            "id": rule.get("id"),
            "groups": groups or [],
        },
        "network": {
            "bytes": total_bytes,
            "packets": _first_non_empty(
                _nested(payload, ("network", "packets")),
                data.get("packets"),
            ),
            "duration": _normalize_duration(
                _first_non_empty(
                    _nested(payload, ("network", "duration")),
                    _nested(payload, ("event", "duration")),
                    data.get("duration"),
                )
            ),
            "protocol": protocol,
        },
        "auth": {"failures": auth_failures},
        "event": {
            "dataset": _first_non_empty(
                _nested(payload, ("event", "dataset")),
                _nested(payload, ("decoder", "name")),
            ),
            "category": _first_non_empty(
                _nested(payload, ("event", "category")),
                _nested(payload, ("event", "module")),
            ),
            "module": _first_non_empty(
                _nested(payload, ("event", "module")),
                _nested(payload, ("decoder", "name")),
            ),
            "duration": _normalize_duration(_nested(payload, ("event", "duration"))),
        },
        "agent": payload.get("agent", {}),
        "labels": {"same_source_hits": same_source_hits},
    }
    return normalized


def _normalize_ecs(payload: Mapping[str, Any]) -> dict[str, Any]:
    source = payload.get("source", {})
    if not isinstance(source, Mapping):
        source = {}
    destination = payload.get("destination", {})
    if not isinstance(destination, Mapping):
        destination = {}
    network = payload.get("network", {})
    if not isinstance(network, Mapping):
        network = {}
    event = payload.get("event", {})
    if not isinstance(event, Mapping):
        event = {}
    rule = payload.get("rule", {})
    if not isinstance(rule, Mapping):
        rule = {}

    category = event.get("category")
    if isinstance(category, list):
        category_text = ", ".join(str(item) for item in category)
    else:
        category_text = category

    normalized = {
        "timestamp": _first_non_empty(payload.get("@timestamp"), payload.get("timestamp")),
        "srcip": _first_non_empty(
            payload.get("srcip"),
            source.get("ip"),
            _nested(payload, ("client", "ip")),
        ),
        "destip": _first_non_empty(
            payload.get("destip"),
            destination.get("ip"),
            _nested(payload, ("server", "ip")),
        ),
        "destport": _first_non_empty(
            payload.get("destport"),
            destination.get("port"),
            network.get("destination_port"),
        ),
        "protocol": _first_non_empty(
            payload.get("protocol"),
            network.get("transport"),
            network.get("protocol"),
        ),
        "message": _first_non_empty(payload.get("message"), event.get("original"), rule.get("description")),
        "action": _first_non_empty(payload.get("action"), event.get("action")),
        "attack_type": _first_non_empty(payload.get("attack_type"), category_text, event.get("type")),
        "rule": {
            "level": _first_non_empty(rule.get("level"), event.get("severity")),
            "description": rule.get("description"),
            "firedtimes": rule.get("firedtimes"),
            "id": rule.get("id"),
            "groups": rule.get("groups", []),
        },
        "network": {
            "bytes": _first_non_empty(network.get("bytes"), payload.get("bytes")),
            "packets": _first_non_empty(network.get("packets"), payload.get("packets")),
            "duration": _normalize_duration(
                _first_non_empty(network.get("duration"), event.get("duration"))
            ),
            "protocol": _first_non_empty(network.get("protocol"), network.get("transport")),
        },
        "auth": {"failures": _first_non_empty(_nested(payload, ("auth", "failures")), event.get("failed"))},
        "event": {
            "dataset": event.get("dataset"),
            "category": category_text,
            "module": event.get("module"),
            "duration": _normalize_duration(event.get("duration")),
        },
        "agent": _first_non_empty(payload.get("agent"), payload.get("host"), {}),
        "labels": {"same_source_hits": _nested(payload, ("labels", "same_source_hits"))},
    }
    return normalized


def normalize_security_event(payload: Mapping[str, Any], source: str = "auto") -> dict[str, Any]:
    source_key = source.lower().strip()
    if source_key not in {"auto", "wazuh", "ecs"}:
        raise ValueError("source must be one of: auto, wazuh, ecs")

    if source_key == "auto":
        if "source" in payload or "destination" in payload or "@timestamp" in payload:
            source_key = "ecs"
        elif "data" in payload or "rule" in payload:
            source_key = "wazuh"
        else:
            source_key = "ecs"

    if source_key == "wazuh":
        return _normalize_wazuh(payload)
    return _normalize_ecs(payload)

