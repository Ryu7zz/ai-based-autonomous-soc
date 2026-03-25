from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.service import DetectionService


def main() -> None:
    service = DetectionService()
    info = service.retrain_demo_model(samples=2200, seed=7)
    print("Model trained successfully")
    print(f"Accuracy: {info.metrics['accuracy']:.4f}")
    print(f"Rows: {info.dataset_rows}")
    print(f"Features: {info.feature_count}")


if __name__ == "__main__":
    main()

