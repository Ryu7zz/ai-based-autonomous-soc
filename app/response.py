from __future__ import annotations

from typing import Any, Mapping


ACTION_MAP = {
    "Normal": [
        "Keep the event for analyst visibility.",
        "Continue passive monitoring for correlated anomalies.",
    ],
    "Brute Force": [
        "Block the source IP on the firewall or Wazuh active response.",
        "Force a credential reset for the targeted account or service.",
        "Increase rate limits and MFA checks on the exposed login surface.",
    ],
    "DDoS": [
        "Apply temporary source blocking and edge rate limiting.",
        "Escalate to the network team for upstream scrubbing if traffic persists.",
        "Protect the targeted service with a tighter traffic profile.",
    ],
    "Port Scan": [
        "Block or tarp it the source IP to reduce reconnaissance.",
        "Review exposed services on the scanned host and close unused ports.",
        "Enrich the source IP with threat-intelligence reputation data.",
    ],
    "Malware": [
        "Quarantine the affected endpoint from the network.",
        "Launch EDR or antivirus scanning on the impacted host.",
        "Preserve artifacts and logs for incident-response triage.",
    ],
}


def severity_from_score(risk_score: float) -> str:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 75:
        return "high"
    if risk_score >= 55:
        return "medium"
    return "low"


def build_active_response_command(label: str, event: Mapping[str, Any]) -> str | None:
    srcip = event.get("srcip")
    host = event.get("agent", {}).get("name") if isinstance(event.get("agent"), dict) else None

    if label in {"Brute Force", "DDoS", "Port Scan"} and srcip:
        return f"iptables -A INPUT -s {srcip} -j DROP"
    if label == "Malware" and host:
        return f"wazuh-control agent quarantine --agent \"{host}\""
    if label == "Malware":
        return "quarantine-endpoint --host <affected-host>"
    return None


def build_response_plan(
    label: str,
    risk_score: float,
    event: Mapping[str, Any],
) -> tuple[str, list[str], bool, str | None]:
    severity = severity_from_score(risk_score)
    actions = ACTION_MAP.get(label, ACTION_MAP["Normal"])
    active_response_enabled = label != "Normal" and risk_score >= 70
    command = build_active_response_command(label, event) if active_response_enabled else None
    return severity, actions, active_response_enabled, command

