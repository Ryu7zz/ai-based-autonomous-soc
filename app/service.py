from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import logging
from pathlib import Path
import sqlite3
from typing import Any, Mapping
from uuid import uuid4

import pandas as pd

from app.config import MODEL_PATH, WEBHOOK_DB_PATH, WEBHOOK_HISTORY_SIZE
from app.features import event_to_features, summarize_event
from app.model import ModelBundle, ensure_model, train_cicids_model, train_demo_model
from app.normalize import normalize_security_event
from app.response import build_response_plan
from app.schemas import ModelInfo, PredictionResponse, StoredWebhookEvent, WebhookEventSummary
from app.storage import WebhookStorage


logger = logging.getLogger(__name__)


class DetectionService:
    def __init__(
        self,
        model_path: Path = MODEL_PATH,
        webhook_db_path: Path | None = WEBHOOK_DB_PATH,
        webhook_history_size: int = WEBHOOK_HISTORY_SIZE,
    ) -> None:
        self.model_path = model_path
        self._bundle: ModelBundle | None = None
        self._webhook_history: deque[dict[str, Any]] = deque(maxlen=webhook_history_size)
        self._storage: WebhookStorage | None = None
        if webhook_db_path is not None:
            try:
                self._storage = WebhookStorage(webhook_db_path)
            except sqlite3.Error as error:
                logger.warning("Webhook storage unavailable, using memory only: %s", error)

    @property
    def bundle(self) -> ModelBundle:
        if self._bundle is None:
            self._bundle = ensure_model(self.model_path)
        return self._bundle

    def retrain_demo_model(self, samples: int = 1800, seed: int = 7) -> ModelInfo:
        self._bundle = train_demo_model(model_path=self.model_path, samples=samples, seed=seed)
        return self.model_info()

    def retrain_from_cicids(
        self,
        csv_path: Path,
        max_rows: int | None = None,
        seed: int = 7,
    ) -> ModelInfo:
        self._bundle = train_cicids_model(
            csv_path=csv_path,
            model_path=self.model_path,
            max_rows=max_rows,
            seed=seed,
        )
        return self.model_info()

    def model_info(self) -> ModelInfo:
        bundle = self.bundle
        return ModelInfo(
            model_name="RandomForestClassifier",
            model_version="0.1.0",
            trained_at=bundle.trained_at,
            dataset_rows=bundle.dataset_rows,
            feature_count=len(bundle.feature_names),
            classes=bundle.classes,
            metrics=bundle.metrics,
        )

    def _risk_score(self, label: str, confidence: float, features: Mapping[str, float]) -> float:
        rule_bonus = min(features["rule_level"] * 1.8, 18.0)
        hint_bonus = min(
            (
                features["bruteforce_hint"]
                + features["ddos_hint"]
                + features["scan_hint"]
                + features["malware_hint"]
            )
            * 4.0,
            16.0,
        )
        velocity_bonus = min(features["packets_per_second"] / 35.0, 12.0)

        if label == "Normal":
            score = confidence * 35.0 + min(features["rule_level"], 5.0)
        else:
            score = confidence * 68.0 + rule_bonus + hint_bonus + velocity_bonus
        return round(float(min(max(score, 1.0), 99.0)), 2)

    def _build_rationale(
        self,
        label: str,
        confidence: float,
        features: Mapping[str, float],
    ) -> list[str]:
        rationale = [f"Model confidence for {label} is {confidence:.1%}."]
        if features["rule_level"] >= 10:
            rationale.append(f"Rule severity is elevated at level {features['rule_level']:.0f}.")
        if features["auth_failures"] >= 5:
            rationale.append("Multiple authentication failures suggest credential abuse.")
        if features["packets_per_second"] >= 120:
            rationale.append("Traffic rate is unusually high for a normal session.")
        if features["scan_hint"] >= 2:
            rationale.append("Reconnaissance-related keywords were found in the event text.")
        if features["malware_hint"] >= 2:
            rationale.append("Malware-oriented indicators appear in the event description.")
        if features["src_is_private"] == 0 and label != "Normal":
            rationale.append("The source IP appears to be external, increasing exposure risk.")
        return rationale

    def analyze_event(self, event: Mapping[str, Any]) -> PredictionResponse:
        features = event_to_features(event)
        vector = pd.DataFrame(
            [{name: features[name] for name in self.bundle.feature_names}],
            columns=self.bundle.feature_names,
        )
        probabilities = self.bundle.model.predict_proba(vector)[0]
        top_index = max(range(len(probabilities)), key=lambda index: probabilities[index])
        label = self.bundle.classes[top_index]
        confidence = round(float(probabilities[top_index]), 4)
        risk_score = self._risk_score(label, confidence, features)
        severity, actions, active_response_enabled, response_command = build_response_plan(
            label,
            risk_score,
            event,
        )
        return PredictionResponse(
            label=label,
            confidence=confidence,
            risk_score=risk_score,
            severity=severity,
            summary=summarize_event(event),
            recommended_actions=actions,
            active_response_enabled=active_response_enabled,
            response_command=response_command,
            rationale=self._build_rationale(label, confidence, features),
            features={name: round(float(value), 3) for name, value in features.items()},
        )

    def analyze_raw_event(
        self,
        payload: Mapping[str, Any],
        source: str = "auto",
    ) -> tuple[PredictionResponse, dict[str, Any]]:
        normalized_event = normalize_security_event(payload, source=source)
        return self.analyze_event(normalized_event), normalized_event

    def ingest_webhook_event(
        self,
        payload: Mapping[str, Any],
        source: str = "wazuh",
    ) -> tuple[PredictionResponse, dict[str, Any], str, str]:
        result, normalized_event = self.analyze_raw_event(payload=payload, source=source)
        processed_at = datetime.now(timezone.utc).isoformat()
        ingestion_id = str(
            payload.get("id")
            or payload.get("alert_id")
            or payload.get("_id")
            or uuid4()
        )

        self._webhook_history.append(
            {
                "ingestion_id": ingestion_id,
                "source": source,
                "processed_at": processed_at,
                "label": result.label,
                "confidence": result.confidence,
                "risk_score": result.risk_score,
                "severity": result.severity,
                "srcip": normalized_event.get("srcip"),
                "destip": normalized_event.get("destip"),
                "destport": normalized_event.get("destport"),
                "active_response_enabled": result.active_response_enabled,
            }
        )
        if self._storage is not None:
            self._storage.save_webhook_event(
                ingestion_id=ingestion_id,
                source=source,
                processed_at=processed_at,
                result=result,
                normalized_event=normalized_event,
                raw_payload=dict(payload),
            )
        return result, normalized_event, ingestion_id, processed_at

    def recent_webhook_events(self, limit: int = 20) -> list[WebhookEventSummary]:
        if self._storage is not None:
            return self._storage.recent_webhook_events(limit=limit)
        clipped_limit = max(min(limit, len(self._webhook_history)), 0)
        if clipped_limit == 0:
            return []
        recent = list(self._webhook_history)[-clipped_limit:]
        recent.reverse()
        return [WebhookEventSummary(**item) for item in recent]

    def webhook_event_by_ingestion_id(self, ingestion_id: str) -> StoredWebhookEvent | None:
        if self._storage is not None:
            return self._storage.webhook_event_by_ingestion_id(ingestion_id)
        for item in reversed(self._webhook_history):
            if item["ingestion_id"] == ingestion_id:
                return StoredWebhookEvent(
                    ingestion_id=item["ingestion_id"],
                    source=item["source"],
                    processed_at=item["processed_at"],
                    result=PredictionResponse(
                        label=item["label"],
                        confidence=float(item["confidence"]),
                        risk_score=float(item["risk_score"]),
                        severity=item["severity"],
                        summary="memory-only history does not persist full payload",
                        recommended_actions=[],
                        active_response_enabled=bool(item["active_response_enabled"]),
                        response_command=None,
                        rationale=[],
                        features={},
                    ),
                    normalized_event={},
                    raw_payload={},
                )
        return None
