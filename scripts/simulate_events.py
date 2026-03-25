from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import SAMPLE_EVENTS_PATH
from app.service import DetectionService


def main() -> None:
    service = DetectionService()
    with SAMPLE_EVENTS_PATH.open("r", encoding="utf-8") as file_pointer:
        events = json.load(file_pointer)

    for item in events:
        result = service.analyze_event(item["event"])
        print(f"\n=== {item['name']} ===")
        print(f"Label: {result.label}")
        print(f"Confidence: {result.confidence:.2%}")
        print(f"Risk score: {result.risk_score}")
        print(f"Severity: {result.severity}")
        if result.response_command:
            print(f"Response: {result.response_command}")


if __name__ == "__main__":
    main()

