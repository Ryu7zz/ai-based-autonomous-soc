from pathlib import Path

import pandas as pd

from app.model import build_cicids_dataset, train_cicids_model


def _build_small_cicids_csv(path: Path) -> None:
    rows: list[dict[str, object]] = []
    labels = [
        "BENIGN",
        "FTP-Patator",
        "DoS Hulk",
        "PortScan",
        "Bot",
    ]
    for offset, label in enumerate(labels):
        for i in range(30):
            rows.append(
                {
                    "Source IP": f"10.0.{offset}.{i % 254 + 1}",
                    "Destination IP": "172.16.0.10",
                    "Destination Port": 443 if label == "BENIGN" else 22 + offset,
                    "Protocol": 6,
                    "Flow Duration": 4_000_000 + (i * 50_000),
                    "Total Fwd Packets": 14 + i,
                    "Total Backward Packets": 8 + i,
                    "Total Length of Fwd Packets": 1200 + (i * 40),
                    "Total Length of Bwd Packets": 900 + (i * 32),
                    "Label": label,
                }
            )
    pd.DataFrame(rows).to_csv(path, index=False)


def test_build_cicids_dataset_maps_labels(tmp_path: Path) -> None:
    csv_path = tmp_path / "cicids.csv"
    _build_small_cicids_csv(csv_path)

    dataset = build_cicids_dataset(csv_path=csv_path, max_rows=180)

    assert {"Normal", "Brute Force", "DDoS", "Port Scan", "Malware"} <= set(dataset["label"])
    assert "rule_level" in dataset.columns
    assert "packets_per_second" in dataset.columns


def test_train_cicids_model(tmp_path: Path) -> None:
    csv_path = tmp_path / "cicids.csv"
    model_path = tmp_path / "trained.pkl"
    _build_small_cicids_csv(csv_path)

    bundle = train_cicids_model(csv_path=csv_path, model_path=model_path, max_rows=180, seed=7)

    assert model_path.exists()
    assert bundle.dataset_rows >= 100
    assert set(bundle.classes) >= {"Normal", "Brute Force", "DDoS", "Port Scan", "Malware"}
