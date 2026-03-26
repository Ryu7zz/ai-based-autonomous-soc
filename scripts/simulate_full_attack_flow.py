from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from fastapi.testclient import TestClient


def build_events() -> list[dict[str, Any]]:
    return [
        {
            "name": "Brute force SSH burst",
            "payload": {
                "timestamp": "2026-03-26T10:21:00Z",
                "rule": {
                    "level": 12,
                    "description": "Multiple authentication failures detected on sshd",
                    "firedtimes": 18,
                    "groups": ["authentication_failed", "sshd"],
                },
                "agent": {"name": "linux-web-01"},
                "data": {
                    "srcip": "185.44.9.10",
                    "dstip": "10.0.0.15",
                    "dstport": "22",
                    "proto": "tcp",
                    "bytes": "18422",
                    "packets": "212",
                    "duration": "25",
                    "failed_attempts": "28",
                },
            },
        },
        {
            "name": "Port scan recon",
            "payload": {
                "timestamp": "2026-03-26T10:22:00Z",
                "rule": {
                    "level": 10,
                    "description": "Potential port scan activity detected",
                    "firedtimes": 9,
                    "groups": ["scan", "network"],
                },
                "data": {
                    "srcip": "203.0.113.77",
                    "dstip": "10.0.0.25",
                    "dstport": "445",
                    "proto": "tcp",
                    "bytes": "12400",
                    "packets": "650",
                    "duration": "8",
                    "failed_attempts": "1",
                },
            },
        },
        {
            "name": "DDoS traffic spike",
            "payload": {
                "timestamp": "2026-03-26T10:23:00Z",
                "rule": {
                    "level": 13,
                    "description": "Traffic spike may indicate DDoS flood",
                    "firedtimes": 11,
                    "groups": ["denial_of_service", "network"],
                },
                "data": {
                    "srcip": "198.51.100.44",
                    "dstip": "10.0.0.80",
                    "dstport": "443",
                    "proto": "tcp",
                    "bytes": "920000",
                    "packets": "8600",
                    "duration": "21",
                },
            },
        },
        {
            "name": "Routine normal access",
            "payload": {
                "timestamp": "2026-03-26T10:24:00Z",
                "rule": {
                    "level": 2,
                    "description": "Routine dashboard access",
                    "firedtimes": 1,
                    "groups": ["web", "access"],
                },
                "data": {
                    "srcip": "10.10.1.9",
                    "dstip": "10.0.0.15",
                    "dstport": "443",
                    "proto": "tcp",
                    "bytes": "3120",
                    "packets": "35",
                    "duration": "11",
                    "failed_attempts": "0",
                },
            },
        },
    ]


def run_live(base_url: str, token: str | None) -> list[dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Webhook-Token"] = token

    results: list[dict[str, Any]] = []
    for event in build_events():
        response = requests.post(
            f"{base_url.rstrip('/')}/api/wazuh/ai/decision?include_normalized=true",
            headers=headers,
            data=json.dumps(event["payload"]),
            timeout=30,
        )
        response.raise_for_status()
        results.append({"name": event["name"], "response": response.json()})
    return results


def run_local() -> list[dict[str, Any]]:
    from app.main import app

    client = TestClient(app)
    results: list[dict[str, Any]] = []
    for event in build_events():
        response = client.post(
            "/api/wazuh/ai/decision?include_normalized=true",
            json=event["payload"],
        )
        response.raise_for_status()
        results.append({"name": event["name"], "response": response.json()})
    return results


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "total_events": len(results),
        "block_true": 0,
        "block_false": 0,
        "rows": [],
    }
    for item in results:
        response = item["response"]
        should_block = bool(response.get("should_block"))
        summary["block_true" if should_block else "block_false"] += 1
        summary["rows"].append(
            {
                "event_name": item["name"],
                "label": response.get("result", {}).get("label"),
                "risk_score": response.get("result", {}).get("risk_score"),
                "should_block": should_block,
                "source_ip": response.get("source_ip"),
                "decision_reason": response.get("decision_reason"),
                "wazuh_block_request": response.get("wazuh_block_request"),
            }
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a full simulated Wazuh->AI attack decision test flow.")
    parser.add_argument("--mode", choices=["local", "live"], default="local")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default=None)
    args = parser.parse_args()

    if args.mode == "local":
        results = run_local()
    else:
        results = run_live(base_url=args.base_url, token=args.token)

    summary = summarize(results)
    output_dir = Path("artifacts")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "simulated_attack_report.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "summary": summary,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("Simulation complete")
    print(f"Mode: {args.mode}")
    print(f"Total events: {summary['total_events']}")
    print(f"Should block: {summary['block_true']}")
    print(f"Allow/Monitor: {summary['block_false']}")
    print(f"Report: {output_path}")
    print("\nPer-event decisions:")
    for row in summary["rows"]:
        print(
            f"- {row['event_name']}: label={row['label']} risk={row['risk_score']} "
            f"should_block={row['should_block']} srcip={row['source_ip']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
