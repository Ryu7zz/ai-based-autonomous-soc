from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.schemas import PredictionResponse, StoredWebhookEvent, WebhookEventSummary


class WebhookStorage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path), timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ingestion_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    srcip TEXT,
                    destip TEXT,
                    destport TEXT,
                    active_response_enabled INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    normalized_event_json TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_webhook_events_processed ON webhook_events(id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_webhook_events_ingestion_id ON webhook_events(ingestion_id)"
            )

    def save_webhook_event(
        self,
        ingestion_id: str,
        source: str,
        processed_at: str,
        result: PredictionResponse,
        normalized_event: dict[str, Any],
        raw_payload: dict[str, Any],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO webhook_events (
                    ingestion_id,
                    source,
                    processed_at,
                    label,
                    confidence,
                    risk_score,
                    severity,
                    srcip,
                    destip,
                    destport,
                    active_response_enabled,
                    result_json,
                    normalized_event_json,
                    raw_payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ingestion_id,
                    source,
                    processed_at,
                    result.label,
                    float(result.confidence),
                    float(result.risk_score),
                    result.severity,
                    normalized_event.get("srcip"),
                    normalized_event.get("destip"),
                    str(normalized_event.get("destport")) if normalized_event.get("destport") is not None else None,
                    1 if result.active_response_enabled else 0,
                    json.dumps(result.model_dump(mode="python"), ensure_ascii=True),
                    json.dumps(normalized_event, ensure_ascii=True),
                    json.dumps(raw_payload, ensure_ascii=True),
                ),
            )

    def recent_webhook_events(self, limit: int = 20) -> list[WebhookEventSummary]:
        safe_limit = max(min(limit, 500), 1)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    ingestion_id,
                    source,
                    processed_at,
                    label,
                    confidence,
                    risk_score,
                    severity,
                    srcip,
                    destip,
                    destport,
                    active_response_enabled
                FROM webhook_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [self._summary_from_row(row) for row in rows]

    def webhook_event_by_ingestion_id(self, ingestion_id: str) -> StoredWebhookEvent | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    ingestion_id,
                    source,
                    processed_at,
                    result_json,
                    normalized_event_json,
                    raw_payload_json
                FROM webhook_events
                WHERE ingestion_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (ingestion_id,),
            ).fetchone()
        if row is None:
            return None
        result_payload = json.loads(row["result_json"])
        return StoredWebhookEvent(
            ingestion_id=row["ingestion_id"],
            source=row["source"],
            processed_at=row["processed_at"],
            result=PredictionResponse(**result_payload),
            normalized_event=json.loads(row["normalized_event_json"]),
            raw_payload=json.loads(row["raw_payload_json"]),
        )

    @staticmethod
    def _summary_from_row(row: sqlite3.Row) -> WebhookEventSummary:
        return WebhookEventSummary(
            ingestion_id=row["ingestion_id"],
            source=row["source"],
            processed_at=row["processed_at"],
            label=row["label"],
            confidence=float(row["confidence"]),
            risk_score=float(row["risk_score"]),
            severity=row["severity"],
            srcip=row["srcip"],
            destip=row["destip"],
            destport=row["destport"],
            active_response_enabled=bool(row["active_response_enabled"]),
        )

