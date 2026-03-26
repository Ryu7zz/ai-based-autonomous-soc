from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

import app.service as service_module
from app.main import app


ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts" / "pptx"


def _build_alert(index: int, high_rule: bool) -> dict[str, Any]:
    level = 12 if high_rule else 2
    return {
        "timestamp": "2026-03-25T10:21:00Z",
        "rule": {
            "level": level,
            "description": "Multiple authentication failures detected on sshd"
            if high_rule
            else "Normal dashboard access",
            "firedtimes": 4,
            "groups": ["authentication_failed", "sshd"] if high_rule else ["web"],
        },
        "agent": {"name": f"host-{index % 8}"},
        "data": {
            "srcip": "185.44.9.10" if high_rule else f"10.10.2.{(index % 200) + 1}",
            "dstip": "10.0.0.15",
            "dstport": "22" if high_rule else "443",
            "proto": "tcp",
            "bytes": str(14000 + index),
            "packets": str(160 + (index % 40)),
            "duration": "12",
            "failed_attempts": "20" if high_rule else "0",
        },
    }


class FakeWazuhClient:
    def iter_alerts(self, max_items: int, batch_size: int = 5000, time_range: str = "30d"):
        for index in range(max_items):
            yield _build_alert(index=index, high_rule=(index % 2 == 0))


def _write_json(name: str, payload: Any) -> None:
    (ARTIFACTS_DIR / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(name: str, text: str) -> None:
    (ARTIFACTS_DIR / name).write_text(text, encoding="utf-8")


def main() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Patch Wazuh integration for deterministic PPT-ready simulation artifacts.
    service_module.WazuhClient = FakeWazuhClient

    client = TestClient(app)

    health = client.get("/api/health").json()
    _write_json("01_health.json", health)

    model_before = client.get("/api/model").json()
    _write_json("02_model_before.json", model_before)

    train_demo = client.post("/api/train/demo", json={"samples": 3000, "seed": 7}).json()
    _write_json("03_train_demo.json", train_demo)

    demo_events = client.get("/api/demo/events").json()
    event = demo_events[0]["event"]
    analyze_event = client.post("/api/analyze", json=event).json()
    _write_json("04_analyze_event.json", analyze_event)

    demo_raw = client.get("/api/demo/raw-events").json()
    analyze_raw = client.post(
        "/api/analyze/raw",
        json={
            "source": demo_raw[0]["source"],
            "include_normalized": True,
            "payload": demo_raw[0]["payload"],
        },
    ).json()
    _write_json("05_analyze_raw.json", analyze_raw)

    webhook_payload = _build_alert(index=1, high_rule=True)
    webhook_ingest = client.post("/api/webhook/wazuh?include_normalized=true", json=webhook_payload).json()
    _write_json("06_webhook_ingest.json", webhook_ingest)

    webhook_events = client.get("/api/webhook/events?limit=5").json()
    _write_json("07_webhook_events.json", webhook_events)

    if webhook_events:
        ingestion_id = webhook_events[0]["ingestion_id"]
        webhook_detail = client.get(f"/api/webhook/events/{ingestion_id}").json()
        _write_json("08_webhook_event_detail.json", webhook_detail)

    train_wazuh = client.post(
        "/api/train/wazuh",
        json={"limit": 100000, "time_range": "30d", "seed": 7},
    ).json()
    _write_json("09_train_wazuh_100k_simulated.json", train_wazuh)

    bulk_wazuh = client.post(
        "/api/analyze/wazuh/bulk",
        json={
            "target_count": 100000,
            "batch_size": 5000,
            "time_range": "30d",
            "include_samples": True,
            "sample_size": 10,
        },
    ).json()
    _write_json("10_bulk_wazuh_100k_simulated.json", bulk_wazuh)

    commands = """# Run app for UI screenshots
uvicorn app.main:app --reload

# Run tests (screenshot this)
PYTHONPATH=. .venv/bin/pytest tests -q

# Generate Wazuh dashboard saved objects
PYTHONPATH=. .venv/bin/python scripts/generate_wazuh_dashboard_ndjson.py

# Generate all PPT-ready API outputs (simulated Wazuh integration including 100000)
PYTHONPATH=. .venv/bin/python scripts/prepare_ppt_artifacts.py
"""
    _write_text("11_commands_to_show.txt", commands)

    checklist = """# Screenshot Checklist (ready order)
1. terminal: uvicorn app.main:app --reload (running)
2. browser: app homepage dashboard
3. browser: /docs endpoint list
4. file open: artifacts/pptx/03_train_demo.json
5. file open: artifacts/pptx/04_analyze_event.json
6. file open: artifacts/pptx/06_webhook_ingest.json
7. file open: artifacts/pptx/07_webhook_events.json
8. file open: artifacts/pptx/09_train_wazuh_100k_simulated.json
9. file open: artifacts/pptx/10_bulk_wazuh_100k_simulated.json
10. terminal: PYTHONPATH=. .venv/bin/pytest tests -q
11. file explorer: data/wazuh_dashboard_saved_objects.ndjson
12. wazuh dashboard: Saved Objects Import screen + imported dashboard
"""
    _write_text("12_screenshot_checklist.md", checklist)

    print(f"PPT artifacts created at: {ARTIFACTS_DIR}")


if __name__ == "__main__":
    main()
