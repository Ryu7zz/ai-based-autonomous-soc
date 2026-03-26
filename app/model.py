from __future__ import annotations

import ipaddress
import pickle
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from app.config import MODEL_PATH, MODELS_DIR
from app.features import FEATURE_NAMES


LABELS = ["Normal", "Brute Force", "DDoS", "Port Scan", "Malware"]


@dataclass
class ModelBundle:
    model: RandomForestClassifier
    feature_names: list[str]
    classes: list[str]
    metrics: dict[str, float]
    trained_at: str
    dataset_rows: int


def _finalize_row(row: dict[str, float]) -> dict[str, float]:
    row["bytes_per_packet"] = row["total_bytes"] / max(row["total_packets"], 1.0)
    row["packets_per_second"] = row["total_packets"] / max(row["duration_seconds"], 1.0)
    return row


def _build_row(rng: np.random.Generator, label: str) -> dict[str, float]:
    if label == "Normal":
        dest_port = int(rng.choice([53, 80, 443, 8080, 3306, 5432]))
        protocol_code = 17.0 if dest_port == 53 else 6.0
        row = {
            "rule_level": float(rng.integers(1, 5)),
            "dest_port": float(dest_port),
            "is_privileged_port": 1.0 if dest_port < 1024 else 0.0,
            "is_ssh_port": 0.0,
            "is_web_port": 1.0 if dest_port in {80, 443, 8080} else 0.0,
            "protocol_code": protocol_code,
            "total_bytes": float(rng.integers(1_200, 90_000)),
            "total_packets": float(rng.integers(8, 280)),
            "duration_seconds": float(rng.uniform(8, 1_200)),
            "auth_failures": float(rng.integers(0, 2)),
            "same_source_hits": float(rng.integers(0, 3)),
            "severity_keyword_hits": float(rng.integers(0, 2)),
            "bruteforce_hint": 0.0,
            "ddos_hint": 0.0,
            "scan_hint": 0.0,
            "malware_hint": 0.0,
            "src_is_private": float(rng.choice([0, 1], p=[0.15, 0.85])),
            "dest_is_private": float(rng.choice([0, 1], p=[0.25, 0.75])),
        }
        return _finalize_row(row)

    if label == "Brute Force":
        dest_port = int(rng.choice([22, 22, 22, 3389, 21]))
        row = {
            "rule_level": float(rng.integers(9, 15)),
            "dest_port": float(dest_port),
            "is_privileged_port": 1.0,
            "is_ssh_port": 1.0,
            "is_web_port": 0.0,
            "protocol_code": 6.0,
            "total_bytes": float(rng.integers(4_000, 40_000)),
            "total_packets": float(rng.integers(80, 650)),
            "duration_seconds": float(rng.uniform(6, 120)),
            "auth_failures": float(rng.integers(8, 45)),
            "same_source_hits": float(rng.integers(5, 18)),
            "severity_keyword_hits": float(rng.integers(2, 6)),
            "bruteforce_hint": float(rng.integers(2, 6)),
            "ddos_hint": 0.0,
            "scan_hint": float(rng.integers(0, 2)),
            "malware_hint": 0.0,
            "src_is_private": float(rng.choice([0, 1], p=[0.8, 0.2])),
            "dest_is_private": 1.0,
        }
        return _finalize_row(row)

    if label == "DDoS":
        dest_port = int(rng.choice([80, 443, 53, 8080]))
        row = {
            "rule_level": float(rng.integers(10, 15)),
            "dest_port": float(dest_port),
            "is_privileged_port": 1.0 if dest_port < 1024 else 0.0,
            "is_ssh_port": 0.0,
            "is_web_port": 1.0 if dest_port in {80, 443, 8080} else 0.0,
            "protocol_code": float(rng.choice([6, 17])),
            "total_bytes": float(rng.integers(150_000, 2_500_000)),
            "total_packets": float(rng.integers(1_000, 22_000)),
            "duration_seconds": float(rng.uniform(1, 90)),
            "auth_failures": 0.0,
            "same_source_hits": float(rng.integers(0, 5)),
            "severity_keyword_hits": float(rng.integers(3, 7)),
            "bruteforce_hint": 0.0,
            "ddos_hint": float(rng.integers(2, 6)),
            "scan_hint": 0.0,
            "malware_hint": 0.0,
            "src_is_private": float(rng.choice([0, 1], p=[0.9, 0.1])),
            "dest_is_private": 1.0,
        }
        return _finalize_row(row)

    if label == "Port Scan":
        dest_port = int(rng.choice([21, 22, 23, 25, 80, 135, 139, 445, 3389]))
        row = {
            "rule_level": float(rng.integers(8, 13)),
            "dest_port": float(dest_port),
            "is_privileged_port": 1.0,
            "is_ssh_port": 1.0 if dest_port in {22, 3389} else 0.0,
            "is_web_port": 1.0 if dest_port == 80 else 0.0,
            "protocol_code": 6.0,
            "total_bytes": float(rng.integers(2_000, 60_000)),
            "total_packets": float(rng.integers(40, 1_500)),
            "duration_seconds": float(rng.uniform(1, 80)),
            "auth_failures": 0.0,
            "same_source_hits": float(rng.integers(8, 35)),
            "severity_keyword_hits": float(rng.integers(2, 5)),
            "bruteforce_hint": 0.0,
            "ddos_hint": 0.0,
            "scan_hint": float(rng.integers(2, 7)),
            "malware_hint": 0.0,
            "src_is_private": float(rng.choice([0, 1], p=[0.8, 0.2])),
            "dest_is_private": 1.0,
        }
        return _finalize_row(row)

    dest_port = int(rng.choice([445, 4444, 8080, 8443, 9001]))
    row = {
        "rule_level": float(rng.integers(10, 15)),
        "dest_port": float(dest_port),
        "is_privileged_port": 1.0 if dest_port < 1024 else 0.0,
        "is_ssh_port": 0.0,
        "is_web_port": 1.0 if dest_port in {8080, 8443} else 0.0,
        "protocol_code": 6.0,
        "total_bytes": float(rng.integers(20_000, 900_000)),
        "total_packets": float(rng.integers(50, 1_600)),
        "duration_seconds": float(rng.uniform(15, 2_400)),
        "auth_failures": float(rng.integers(0, 3)),
        "same_source_hits": float(rng.integers(1, 10)),
        "severity_keyword_hits": float(rng.integers(3, 7)),
        "bruteforce_hint": 0.0,
        "ddos_hint": 0.0,
        "scan_hint": 0.0,
        "malware_hint": float(rng.integers(2, 7)),
        "src_is_private": 1.0,
        "dest_is_private": float(rng.choice([0, 1], p=[0.55, 0.45])),
    }
    return _finalize_row(row)


def build_demo_dataset(samples: int = 1800, seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    weights = {
        "Normal": 0.50,
        "Brute Force": 0.18,
        "DDoS": 0.14,
        "Port Scan": 0.10,
        "Malware": 0.08,
    }
    rows: list[dict[str, float | str]] = []
    for label, weight in weights.items():
        count = int(samples * weight)
        for _ in range(count):
            row = _build_row(rng, label)
            row["label"] = label
            rows.append(row)

    df = pd.DataFrame(rows)
    missing_columns = [name for name in FEATURE_NAMES if name not in df.columns]
    if missing_columns:
        raise ValueError(f"Dataset generation missed features: {missing_columns}")
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _normalize_column_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def _numeric_series(df: pd.DataFrame, candidates: Iterable[str], default: float = 0.0) -> pd.Series:
    for candidate in candidates:
        if candidate in df.columns:
            return pd.to_numeric(df[candidate], errors="coerce").fillna(default).astype(float)
    return pd.Series(default, index=df.index, dtype=float)


def _text_series(df: pd.DataFrame, candidates: Iterable[str], default: str = "") -> pd.Series:
    for candidate in candidates:
        if candidate in df.columns:
            return df[candidate].fillna(default).astype(str)
    return pd.Series(default, index=df.index, dtype=object)


def _private_flags(values: pd.Series) -> pd.Series:
    def parse(value: str) -> float:
        text = str(value).strip()
        if not text:
            return 0.0
        try:
            return 1.0 if ipaddress.ip_address(text).is_private else 0.0
        except ValueError:
            return 0.0

    return values.map(parse).astype(float)


def map_cicids_label(raw_label: str) -> str:
    label = raw_label.strip().lower()
    if label in {"benign", "normal"}:
        return "Normal"
    if "patator" in label or "brute" in label or "credential" in label:
        return "Brute Force"
    if "ddos" in label or "dos" in label or "slowloris" in label or "hulk" in label:
        return "DDoS"
    if "portscan" in label or "port scan" in label or "scan" in label:
        return "Port Scan"
    return "Malware"


def _rule_level_for_label(label: str) -> float:
    return {
        "Normal": 3.0,
        "Brute Force": 12.0,
        "DDoS": 13.0,
        "Port Scan": 10.0,
        "Malware": 12.0,
    }.get(label, 8.0)


def _rows_from_cicids(raw: pd.DataFrame) -> pd.DataFrame:
    df = raw.copy()
    df.columns = [_normalize_column_name(column) for column in df.columns]
    if "label" not in df.columns:
        raise ValueError("CIC-IDS CSV must include a 'Label' column.")

    label_text = df["label"].fillna("Unknown").astype(str)
    mapped_label = label_text.map(map_cicids_label)

    destination_port = _numeric_series(
        df,
        ["destination_port", "dest_port", "dst_port", "dstport"],
    )
    protocol_code = _numeric_series(df, ["protocol", "proto"], default=0.0)
    flow_duration_raw = _numeric_series(df, ["flow_duration", "duration"], default=0.0)
    duration_seconds = flow_duration_raw.where(flow_duration_raw <= 100_000, flow_duration_raw / 1_000_000)

    total_fwd_packets = _numeric_series(
        df,
        ["total_fwd_packets", "tot_fwd_pkts", "total_forward_packets"],
    )
    total_bwd_packets = _numeric_series(
        df,
        ["total_backward_packets", "tot_bwd_pkts", "total_bwd_packets"],
    )
    total_packets = total_fwd_packets + total_bwd_packets
    total_packets = total_packets.where(total_packets > 0, _numeric_series(df, ["total_packets"], default=0.0))

    total_fwd_bytes = _numeric_series(
        df,
        [
            "total_length_of_fwd_packets",
            "totlen_fwd_pkts",
            "fwd_packet_length_total",
            "fwd_pkt_len_tot",
        ],
    )
    total_bwd_bytes = _numeric_series(
        df,
        [
            "total_length_of_bwd_packets",
            "totlen_bwd_pkts",
            "bwd_packet_length_total",
            "bwd_pkt_len_tot",
        ],
    )
    total_bytes = total_fwd_bytes + total_bwd_bytes
    total_bytes = total_bytes.where(total_bytes > 0, _numeric_series(df, ["total_bytes"], default=0.0))

    flow_packets_per_second = _numeric_series(df, ["flow_packets_s", "flow_pkts_s"], default=0.0)
    packets_per_second = total_packets / duration_seconds.clip(lower=1.0)
    packets_per_second = packets_per_second.where(packets_per_second > 0, flow_packets_per_second)
    bytes_per_packet = total_bytes / total_packets.clip(lower=1.0)

    auth_failures = _numeric_series(df, ["auth_failures", "failed_logins"], default=0.0)
    brute_force_mask = mapped_label == "Brute Force"
    estimated_failures = (total_packets * 0.04).clip(lower=6.0, upper=40.0)
    auth_failures = auth_failures.where(auth_failures > 0, estimated_failures.where(brute_force_mask, 0.0))

    same_source_hits = _numeric_series(df, ["same_source_hits"], default=0.0)
    inferred_hits = (packets_per_second / 3.0).clip(lower=0.0, upper=50.0)
    same_source_hits = same_source_hits.where(same_source_hits > 0, inferred_hits)

    lower_label = label_text.str.lower()
    bruteforce_hint = lower_label.str.contains(r"patator|brute|credential", regex=True).astype(float) * 3.0
    ddos_hint = lower_label.str.contains(r"ddos|dos|slowloris|hulk|goldeneye", regex=True).astype(float) * 3.0
    scan_hint = lower_label.str.contains(r"portscan|port scan|scan", regex=True).astype(float) * 3.0
    malware_hint = lower_label.str.contains(
        r"bot|infiltration|heartbleed|web attack|xss|sql injection|malware|trojan",
        regex=True,
    ).astype(float) * 3.0
    severity_keyword_hits = (
        bruteforce_hint.gt(0).astype(float)
        + ddos_hint.gt(0).astype(float)
        + scan_hint.gt(0).astype(float)
        + malware_hint.gt(0).astype(float)
    )

    source_ip = _text_series(df, ["source_ip", "src_ip", "srcip"], default="")
    destination_ip = _text_series(df, ["destination_ip", "dst_ip", "destip"], default="")

    cicids_df = pd.DataFrame(
        {
            "rule_level": mapped_label.map(_rule_level_for_label).astype(float),
            "dest_port": destination_port,
            "is_privileged_port": destination_port.between(1, 1023).astype(float),
            "is_ssh_port": destination_port.isin([21, 22, 3389]).astype(float),
            "is_web_port": destination_port.isin([80, 443, 8080, 8443]).astype(float),
            "protocol_code": protocol_code,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "duration_seconds": duration_seconds.clip(lower=0.0),
            "bytes_per_packet": bytes_per_packet,
            "packets_per_second": packets_per_second.clip(lower=0.0),
            "auth_failures": auth_failures.clip(lower=0.0),
            "same_source_hits": same_source_hits.clip(lower=0.0),
            "severity_keyword_hits": severity_keyword_hits,
            "bruteforce_hint": bruteforce_hint,
            "ddos_hint": ddos_hint,
            "scan_hint": scan_hint,
            "malware_hint": malware_hint,
            "src_is_private": _private_flags(source_ip),
            "dest_is_private": _private_flags(destination_ip),
            "label": mapped_label,
        }
    )

    for feature in FEATURE_NAMES:
        cicids_df[feature] = pd.to_numeric(cicids_df[feature], errors="coerce").fillna(0.0)

    cicids_df = cicids_df.replace([np.inf, -np.inf], np.nan).dropna(subset=["label"])
    return cicids_df


def load_cicids_dataframe(csv_path: Path, max_rows: int | None = None) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"CIC-IDS source not found: {csv_path}")

    if csv_path.is_dir():
        csv_files = sorted(path for path in csv_path.glob("*.csv") if path.is_file())
    else:
        csv_files = [csv_path]
    if not csv_files:
        raise ValueError("No CSV files found in the provided CIC-IDS path.")

    frames: list[pd.DataFrame] = []
    remaining_rows = max_rows
    for file_path in csv_files:
        nrows = remaining_rows if remaining_rows is not None else None
        try:
            frame = pd.read_csv(file_path, low_memory=False, nrows=nrows)
        except UnicodeDecodeError:
            frame = pd.read_csv(file_path, low_memory=False, nrows=nrows, encoding="latin1")
        frames.append(frame)

        if remaining_rows is not None:
            remaining_rows -= len(frame)
            if remaining_rows <= 0:
                break

    return pd.concat(frames, ignore_index=True)


def build_cicids_dataset(csv_path: Path, max_rows: int | None = None) -> pd.DataFrame:
    raw = load_cicids_dataframe(csv_path=csv_path, max_rows=max_rows)
    return _rows_from_cicids(raw)


def rebalance_normal_attack_ratio(
    dataframe: pd.DataFrame,
    normal_ratio: float = 0.8,
    seed: int = 7,
) -> pd.DataFrame:
    if "label" not in dataframe.columns:
        raise ValueError("Dataset must include 'label' column for ratio balancing.")

    df = dataframe.copy()
    labels = df["label"].astype(str)
    normal_df = df[labels == "Normal"]
    attack_df = df[labels != "Normal"]
    if normal_df.empty or attack_df.empty:
        raise ValueError("CICIDS rebalance needs both Normal and Attack rows.")

    target_normal_ratio = float(normal_ratio)
    target_attack_ratio = 1.0 - target_normal_ratio
    if not (0.0 < target_attack_ratio < 1.0):
        raise ValueError("normal_ratio must be between 0 and 1.")

    # Keep as many rows as possible while matching the desired ratio.
    max_total_by_normal = int(len(normal_df) / target_normal_ratio)
    max_total_by_attack = int(len(attack_df) / target_attack_ratio)
    target_total = max(min(max_total_by_normal, max_total_by_attack), 2)

    normal_target = int(round(target_total * target_normal_ratio))
    attack_target = max(target_total - normal_target, 1)

    sampled_normal = normal_df.sample(n=min(normal_target, len(normal_df)), random_state=seed)

    attack_parts: list[pd.DataFrame] = []
    attack_groups = [frame for _, frame in attack_df.groupby(attack_df["label"].astype(str))]
    per_group = max(attack_target // max(len(attack_groups), 1), 1)
    remaining = attack_target
    for index, group in enumerate(attack_groups):
        take = per_group if index < len(attack_groups) - 1 else remaining
        sampled = group.sample(n=min(take, len(group)), random_state=seed + index)
        attack_parts.append(sampled)
        remaining = max(remaining - len(sampled), 0)

    sampled_attack = pd.concat(attack_parts, ignore_index=False)
    if len(sampled_attack) < attack_target:
        extra_needed = attack_target - len(sampled_attack)
        refill = attack_df.sample(n=min(extra_needed, len(attack_df)), random_state=seed + 97)
        sampled_attack = pd.concat([sampled_attack, refill], ignore_index=False)

    balanced = pd.concat([sampled_normal, sampled_attack], ignore_index=False)
    return balanced.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _train_from_dataframe(
    dataframe: pd.DataFrame,
    model_path: Path,
    seed: int = 7,
) -> ModelBundle:
    required_columns = set(FEATURE_NAMES + ["label"])
    missing_columns = sorted(required_columns - set(dataframe.columns))
    if missing_columns:
        raise ValueError(f"Training dataset missing columns: {missing_columns}")

    train_df = dataframe[FEATURE_NAMES + ["label"]].copy()
    train_df = train_df.replace([np.inf, -np.inf], np.nan).dropna()
    if len(train_df) < 100:
        raise ValueError("Training dataset is too small. At least 100 valid rows are required.")
    if train_df["label"].nunique() < 2:
        raise ValueError("Training dataset must contain at least 2 distinct labels.")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    X = train_df[FEATURE_NAMES]
    y = train_df["label"].astype(str)

    class_counts = y.value_counts()
    stratify_target = y if int(class_counts.min()) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=seed,
        stratify=stratify_target,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=14,
        min_samples_leaf=2,
        random_state=seed,
        class_weight="balanced_subsample",
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "macro_precision": round(float(report["macro avg"]["precision"]), 4),
        "macro_recall": round(float(report["macro avg"]["recall"]), 4),
        "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
    }

    trained_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "classes": list(model.classes_),
        "metrics": metrics,
        "trained_at": trained_at,
        "dataset_rows": int(len(train_df)),
    }
    with model_path.open("wb") as file_pointer:
        pickle.dump(payload, file_pointer)

    return ModelBundle(
        model=model,
        feature_names=FEATURE_NAMES,
        classes=list(model.classes_),
        metrics=metrics,
        trained_at=trained_at,
        dataset_rows=int(len(train_df)),
    )


def train_demo_model(model_path: Path = MODEL_PATH, samples: int = 1800, seed: int = 7) -> ModelBundle:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    dataset = build_demo_dataset(samples=samples, seed=seed)
    return _train_from_dataframe(dataframe=dataset, model_path=model_path, seed=seed)


def train_cicids_model(
    csv_path: Path,
    model_path: Path = MODEL_PATH,
    max_rows: int | None = None,
    normal_ratio: float = 0.8,
    seed: int = 7,
) -> ModelBundle:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    original_dataset = build_cicids_dataset(csv_path=csv_path, max_rows=max_rows)
    dataset = rebalance_normal_attack_ratio(
        dataframe=original_dataset,
        normal_ratio=normal_ratio,
        seed=seed,
    )
    if len(dataset) < 100 and len(original_dataset) >= 100:
        # Keep training usable on small synthetic inputs while preserving ratio for real CICIDS-scale datasets.
        dataset = original_dataset
    return _train_from_dataframe(dataframe=dataset, model_path=model_path, seed=seed)


def load_model_bundle(model_path: Path = MODEL_PATH) -> ModelBundle:
    with model_path.open("rb") as file_pointer:
        payload = pickle.load(file_pointer)
    return ModelBundle(
        model=payload["model"],
        feature_names=list(payload["feature_names"]),
        classes=list(payload["classes"]),
        metrics=dict(payload["metrics"]),
        trained_at=str(payload["trained_at"]),
        dataset_rows=int(payload["dataset_rows"]),
    )


def ensure_model(model_path: Path = MODEL_PATH) -> ModelBundle:
    if not model_path.exists():
        return train_demo_model(model_path=model_path)
    return load_model_bundle(model_path=model_path)

