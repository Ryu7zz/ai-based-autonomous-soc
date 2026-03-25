from __future__ import annotations

import ipaddress
from typing import Any, Mapping


FEATURE_NAMES = [
    "rule_level",
    "dest_port",
    "is_privileged_port",
    "is_ssh_port",
    "is_web_port",
    "protocol_code",
    "total_bytes",
    "total_packets",
    "duration_seconds",
    "bytes_per_packet",
    "packets_per_second",
    "auth_failures",
    "same_source_hits",
    "severity_keyword_hits",
    "bruteforce_hint",
    "ddos_hint",
    "scan_hint",
    "malware_hint",
    "src_is_private",
    "dest_is_private",
]

PROTOCOL_CODES = {"icmp": 1, "tcp": 6, "udp": 17}

KEYWORD_GROUPS = {
    "severity_keyword_hits": [
        "attack",
        "blocked",
        "denied",
        "failure",
        "flood",
        "malware",
        "scan",
        "suspicious",
    ],
    "bruteforce_hint": [
        "authentication failure",
        "brute force",
        "credential stuffing",
        "login failed",
        "password spraying",
        "ssh",
    ],
    "ddos_hint": [
        "ddos",
        "flood",
        "syn flood",
        "traffic spike",
        "volumetric",
    ],
    "scan_hint": [
        "nmap",
        "port sweep",
        "port scan",
        "probing",
        "recon",
        "scan",
    ],
    "malware_hint": [
        "beacon",
        "c2",
        "command and control",
        "malware",
        "payload",
        "ransomware",
        "trojan",
    ],
}


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


def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.replace(",", "").strip()
        if not cleaned:
            return default
        try:
            return float(cleaned)
        except ValueError:
            return default
    return default


def _safe_private_flag(address: Any) -> float:
    if not address:
        return 0.0
    try:
        return 1.0 if ipaddress.ip_address(str(address)).is_private else 0.0
    except ValueError:
        return 0.0


def _collect_text(event: Mapping[str, Any]) -> str:
    text_parts: list[str] = []
    for value in [
        event.get("message"),
        event.get("attack_type"),
        event.get("action"),
        _nested(event, ("rule", "description")),
        _nested(event, ("event", "dataset")),
        _nested(event, ("event", "category")),
        _nested(event, ("event", "module")),
    ]:
        if value:
            text_parts.append(str(value))
    return " ".join(text_parts).lower()


def _count_keywords(text: str, keywords: list[str]) -> float:
    return float(sum(1 for keyword in keywords if keyword in text))


def event_to_features(event: Mapping[str, Any]) -> dict[str, float]:
    rule_level = _to_float(
        _nested(event, ("rule", "level"), ("labels", "rule_level"), "level"),
        default=1.0,
    )
    dest_port = _to_float(
        event.get("destport")
        or _nested(event, ("network", "destport"))
        or _nested(event, ("destination", "port")),
        default=0.0,
    )
    total_bytes = _to_float(
        _nested(event, ("network", "bytes"), ("network", "total_bytes"), "bytes"),
        default=0.0,
    )
    total_packets = _to_float(
        _nested(event, ("network", "packets"), ("network", "total_packets"), "packets"),
        default=0.0,
    )
    duration_seconds = _to_float(
        _nested(event, ("network", "duration"), ("event", "duration"), "duration"),
        default=0.0,
    )
    auth_failures = _to_float(
        _nested(
            event,
            ("auth", "failures"),
            ("event", "failures"),
            ("rule", "firedtimes"),
            ("labels", "same_source_hits"),
        ),
        default=0.0,
    )
    same_source_hits = _to_float(
        _nested(
            event,
            ("labels", "same_source_hits"),
            ("event", "same_source_hits"),
            ("rule", "firedtimes"),
        ),
        default=0.0,
    )
    protocol = (
        str(
            event.get("protocol")
            or _nested(event, ("network", "protocol"))
            or _nested(event, ("network", "transport"))
            or _nested(event, ("network", "protocol_number"))
            or ""
        )
        .strip()
        .lower()
    )
    protocol_code = float(PROTOCOL_CODES.get(protocol, 0))

    text = _collect_text(event)
    severity_keyword_hits = _count_keywords(text, KEYWORD_GROUPS["severity_keyword_hits"])
    bruteforce_hint = _count_keywords(text, KEYWORD_GROUPS["bruteforce_hint"])
    ddos_hint = _count_keywords(text, KEYWORD_GROUPS["ddos_hint"])
    scan_hint = _count_keywords(text, KEYWORD_GROUPS["scan_hint"])
    malware_hint = _count_keywords(text, KEYWORD_GROUPS["malware_hint"])

    bytes_per_packet = total_bytes / max(total_packets, 1.0)
    packets_per_second = total_packets / max(duration_seconds, 1.0)

    features = {
        "rule_level": rule_level,
        "dest_port": dest_port,
        "is_privileged_port": 1.0 if 0 < dest_port < 1024 else 0.0,
        "is_ssh_port": 1.0 if dest_port in {22, 2222, 3389} else 0.0,
        "is_web_port": 1.0 if dest_port in {80, 443, 8080, 8443} else 0.0,
        "protocol_code": protocol_code,
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "duration_seconds": duration_seconds,
        "bytes_per_packet": bytes_per_packet,
        "packets_per_second": packets_per_second,
        "auth_failures": auth_failures,
        "same_source_hits": same_source_hits,
        "severity_keyword_hits": severity_keyword_hits,
        "bruteforce_hint": bruteforce_hint,
        "ddos_hint": ddos_hint,
        "scan_hint": scan_hint,
        "malware_hint": malware_hint,
        "src_is_private": _safe_private_flag(
            event.get("srcip")
            or _nested(event, ("source", "ip"))
            or _nested(event, ("client", "ip"))
        ),
        "dest_is_private": _safe_private_flag(
            event.get("destip")
            or _nested(event, ("destination", "ip"))
            or _nested(event, ("server", "ip"))
        ),
    }
    return features


def summarize_event(event: Mapping[str, Any]) -> str:
    src = event.get("srcip") or _nested(event, ("source", "ip")) or "unknown-source"
    dest = event.get("destip") or _nested(event, ("destination", "ip")) or "unknown-destination"
    port = event.get("destport") or _nested(event, ("destination", "port")) or "n/a"
    protocol = event.get("protocol") or _nested(event, ("network", "protocol")) or "unknown"
    return f"{src} -> {dest}:{port} over {protocol}"
