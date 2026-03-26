from __future__ import annotations

from collections import deque
from collections import defaultdict
from datetime import datetime, timezone
import logging
from pathlib import Path
import sqlite3
from typing import Any, Mapping
from uuid import uuid4

import pandas as pd

from app.config import MODEL_PATH, WAZUH_MAX_BULK_ANALYSIS, WEBHOOK_DB_PATH, WEBHOOK_HISTORY_SIZE
from app.features import event_to_features, summarize_event
from app.model import ModelBundle, ensure_model, train_cicids_model, train_demo_model
from app.normalize import normalize_security_event
from app.response import build_response_plan
from app.schemas import (
    ModelInfo,
    PredictionResponse,
    WazuhBlockRequest,
    WazuhDecisionResponse,
    WazuhDecisionBoardResponse,
    WazuhDecisionLogEntry,
    StoredWebhookEvent,
    WazuhBulkAnalyzeResponse,
    WebhookEventSummary,
)
from app.storage import WebhookStorage
from app.wazuh_client import WazuhClient


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

    def retrain_from_wazuh(self, limit: int = 100000, time_range: str = "30d", seed: int = 7) -> ModelInfo:
        logger.info("Retraining model from Wazuh with limit %s over %s", limit, time_range)
        client = WazuhClient()
        features_list: list[dict[str, float]] = []
        labels: list[str] = []
        try:
            for alert in client.iter_alerts(max_items=limit, batch_size=5000, time_range=time_range):
                normalized = normalize_security_event(alert, source="wazuh")
                features = event_to_features(normalized)
                features_list.append(features)
                labels.append("Incident" if features.get("rule_level", 0.0) > 4 else "Normal")
        except Exception as error:
            logger.error("Error fetching Wazuh alerts: %s", error)
            raise ValueError(f"Wazuh fetch failed: {error}") from error

        if len(labels) < 50:
            logger.warning("Not enough data from Wazuh, falling back to demo model")
            fallback_samples = max(min(limit, 20000), 1800)
            return self.retrain_demo_model(samples=fallback_samples, seed=seed)

        df = pd.DataFrame(features_list)
        if df.empty:
            raise ValueError("No trainable data returned from Wazuh alerts.")

        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

        clf = RandomForestClassifier(n_estimators=100, random_state=seed)
        clf.fit(df, labels)
        preds = clf.predict(df)

        bundle = ModelBundle(
            model=clf,
            feature_names=list(df.columns),
            classes=list(clf.classes_),
            trained_at=datetime.now(timezone.utc).isoformat(),
            dataset_rows=len(labels),
            metrics={
                "accuracy": accuracy_score(labels, preds),
                "precision": precision_score(labels, preds, average="macro", zero_division=0),
                "recall": recall_score(labels, preds, average="macro", zero_division=0),
                "f1": f1_score(labels, preds, average="macro", zero_division=0),
            },
        )

        import pickle

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, "wb") as file_pointer:
            pickle.dump(bundle, file_pointer)

        self._bundle = bundle
        return self.model_info()

    def analyze_wazuh_bulk(
        self,
        target_count: int = 100000,
        batch_size: int = 5000,
        time_range: str = "30d",
        include_samples: bool = False,
        sample_size: int = 20,
    ) -> WazuhBulkAnalyzeResponse:
        capped_target = max(min(int(target_count), WAZUH_MAX_BULK_ANALYSIS), 1)
        client = WazuhClient()

        label_counts: dict[str, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)
        sample_results: list[PredictionResponse] = []
        analyzed_count = 0
        total_risk = 0.0
        high_risk_count = 0

        try:
            for alert in client.iter_alerts(
                max_items=capped_target,
                batch_size=batch_size,
                time_range=time_range,
            ):
                result, _ = self.analyze_raw_event(payload=alert, source="wazuh")
                analyzed_count += 1
                label_counts[result.label] += 1
                severity_counts[result.severity] += 1
                total_risk += result.risk_score
                if result.risk_score >= 75.0:
                    high_risk_count += 1
                if include_samples and len(sample_results) < sample_size:
                    sample_results.append(result)
        except Exception as error:
            raise ValueError(f"Wazuh bulk analysis failed: {error}") from error

        average_risk = round(total_risk / analyzed_count, 2) if analyzed_count else 0.0
        return WazuhBulkAnalyzeResponse(
            requested_count=capped_target,
            analyzed_count=analyzed_count,
            label_counts=dict(label_counts),
            severity_counts=dict(severity_counts),
            average_risk_score=average_risk,
            high_risk_count=high_risk_count,
            top_samples=sample_results,
        )

    def wazuh_decision_board(
        self,
        limit: int = 200,
        time_range: str = "24h",
    ) -> WazuhDecisionBoardResponse:
        capped_limit = max(min(int(limit), 2000), 1)
        client = WazuhClient()
        alerts = list(
            client.iter_alerts(
                max_items=capped_limit,
                batch_size=min(500, capped_limit),
                time_range=time_range,
            )
        )

        blocked_by_source: dict[str, dict[str, str | None]] = {}
        for alert in alerts:
            if not isinstance(alert, Mapping):
                continue
            rule = alert.get("rule", {})
            if not isinstance(rule, Mapping):
                rule = {}
            rule_id = str(rule.get("id") or "")
            description = str(rule.get("description") or "")
            full_log = str(alert.get("full_log") or "")
            is_block_event = (
                rule_id == "651"
                or "firewall-drop" in description.lower()
                or "firewall-drop" in full_log.lower()
            )
            if not is_block_event:
                continue
            normalized = normalize_security_event(alert, source="wazuh")
            srcip = normalized.get("srcip")
            if not srcip:
                continue
            blocked_by_source[str(srcip)] = {
                "event_id": str(alert.get("id") or "") or None,
                "timestamp": str(alert.get("timestamp") or "") or None,
                "rule_id": rule_id or None,
            }

        rows: list[WazuhDecisionLogEntry] = []
        blocked_count = 0
        should_block_count = 0
        monitor_count = 0

        for alert in alerts:
            if not isinstance(alert, Mapping):
                continue
            result, normalized = self.analyze_raw_event(payload=alert, source="wazuh")

            rule = alert.get("rule", {})
            if not isinstance(rule, Mapping):
                rule = {}

            srcip = normalized.get("srcip")
            block_evidence = blocked_by_source.get(str(srcip)) if srcip else None

            if block_evidence:
                decision = "blocked"
                decision_reason = "Wazuh active response already blocked this source IP."
                blocked_count += 1
            elif result.active_response_enabled:
                decision = "should_block"
                decision_reason = "AI marked this as high risk and recommends active response."
                should_block_count += 1
            else:
                decision = "monitor"
                decision_reason = "Low risk right now; keep monitoring and correlate with future alerts."
                monitor_count += 1

            rows.append(
                WazuhDecisionLogEntry(
                    timestamp=str(alert.get("timestamp") or "") or None,
                    event_id=str(alert.get("id") or "") or None,
                    wazuh_rule_id=str(rule.get("id") or "") or None,
                    wazuh_rule_description=str(rule.get("description") or "") or None,
                    source_ip=str(srcip) if srcip else None,
                    destination_ip=str(normalized.get("destip") or "") or None,
                    destination_port=normalized.get("destport"),
                    model_label=result.label,
                    model_confidence=result.confidence,
                    risk_score=result.risk_score,
                    severity=result.severity,
                    decision=decision,
                    decision_reason=decision_reason,
                    response_command=result.response_command,
                    blocked_by_wazuh=block_evidence is not None,
                    block_event_id=block_evidence["event_id"] if block_evidence else None,
                    block_event_timestamp=block_evidence["timestamp"] if block_evidence else None,
                    block_event_rule_id=block_evidence["rule_id"] if block_evidence else None,
                    summary=result.summary,
                    full_log=str(alert.get("full_log") or "") or None,
                )
            )

        return WazuhDecisionBoardResponse(
            requested_count=capped_limit,
            analyzed_count=len(rows),
            blocked_count=blocked_count,
            should_block_count=should_block_count,
            monitor_count=monitor_count,
            rows=rows,
        )

    def retrain_from_cicids(
        self,
        csv_path: Path,
        max_rows: int | None = None,
        normal_ratio: float = 0.8,
        seed: int = 7,
    ) -> ModelInfo:
        self._bundle = train_cicids_model(
            csv_path=csv_path,
            model_path=self.model_path,
            max_rows=max_rows,
            normal_ratio=normal_ratio,
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

    def decide_wazuh_event(
        self,
        payload: Mapping[str, Any],
        include_normalized: bool = False,
    ) -> WazuhDecisionResponse:
        result, normalized_event, ingestion_id, processed_at = self.ingest_webhook_event(
            payload=payload,
            source="wazuh",
        )

        srcip = normalized_event.get("srcip")
        should_block = bool(result.active_response_enabled and srcip)

        if should_block:
            decision_reason = "High-risk event: Random Forest recommends Wazuh firewall-drop active response."
            block_request = WazuhBlockRequest(
                command="firewall-drop",
                srcip=str(srcip),
                timeout=600,
                reason=f"AI decision from AutomaticSOC (risk={result.risk_score}, label={result.label})",
            )
        elif result.active_response_enabled and not srcip:
            decision_reason = "High risk detected, but source IP is missing so block action cannot be safely requested."
            block_request = None
        else:
            decision_reason = "AI marked this event as monitor/allow. Do not block from Wazuh for this event."
            block_request = None

        return WazuhDecisionResponse(
            status="decision_ready",
            ingestion_id=ingestion_id,
            source="wazuh",
            processed_at=processed_at,
            should_block=should_block,
            decision_reason=decision_reason,
            source_ip=str(srcip) if srcip else None,
            result=result,
            wazuh_block_request=block_request,
            normalized_event=normalized_event if include_normalized else None,
        )

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
