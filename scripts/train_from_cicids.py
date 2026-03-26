from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.service import DetectionService


def main() -> None:
    parser = argparse.ArgumentParser(description="Train AutomaticSOC model from CIC-IDS CSV data.")
    parser.add_argument("csv_path", help="Path to a CIC-IDS CSV file or directory of CSV files.")
    parser.add_argument("--max-rows", type=int, default=250000, help="Maximum rows to load.")
    parser.add_argument("--normal-ratio", type=float, default=0.8, help="Target Normal ratio (e.g. 0.8).")
    parser.add_argument("--seed", type=int, default=7, help="Random seed for training.")
    args = parser.parse_args()

    service = DetectionService()
    info = service.retrain_from_cicids(
        csv_path=Path(args.csv_path).expanduser(),
        max_rows=args.max_rows,
        normal_ratio=args.normal_ratio,
        seed=args.seed,
    )
    print("CIC-IDS model training completed")
    print(f"Accuracy: {info.metrics['accuracy']:.4f}")
    print(f"Rows: {info.dataset_rows}")
    print(f"Classes: {', '.join(info.classes)}")


if __name__ == "__main__":
    main()

