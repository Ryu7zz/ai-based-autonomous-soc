from __future__ import annotations

from datetime import datetime
from typing import Any
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SecurityEvent(BaseModel):
    timestamp: datetime | None = None
    srcip: str | None = None
    destip: str | None = None
    destport: int | str | None = None
    protocol: str | None = None
    message: str | None = None
    action: str | None = None
    attack_type: str | None = None
    rule: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    auth: dict[str, Any] = Field(default_factory=dict)
    event: dict[str, Any] = Field(default_factory=dict)
    agent: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class TrainRequest(BaseModel):
    samples: int = Field(default=1800, ge=500, le=20000)
    seed: int = Field(default=7, ge=1, le=999999)


class CICIDSTrainRequest(BaseModel):
    csv_path: str
    max_rows: int | None = Field(default=250000, ge=100, le=5_000_000)
    normal_ratio: float = Field(default=0.8, ge=0.5, le=0.95)
    seed: int = Field(default=7, ge=1, le=999999)


class WazuhTrainRequest(BaseModel):
    limit: int = Field(default=100000, ge=1000, le=1_000_000)
    time_range: str = "30d"
    seed: int = Field(default=7, ge=1, le=999999)


class WazuhBulkAnalyzeRequest(BaseModel):
    target_count: int = Field(default=100000, ge=1000, le=1_000_000)
    batch_size: int = Field(default=5000, ge=100, le=25000)
    time_range: str = "30d"
    include_samples: bool = False
    sample_size: int = Field(default=20, ge=1, le=200)


class ModelInfo(BaseModel):
    model_name: str
    model_version: str
    trained_at: str
    dataset_rows: int
    feature_count: int
    classes: list[str]
    metrics: dict[str, float]


class PredictionResponse(BaseModel):
    label: str
    confidence: float
    risk_score: float
    severity: str
    summary: str
    recommended_actions: list[str]
    active_response_enabled: bool
    response_command: str | None = None
    rationale: list[str]
    features: dict[str, float]


class BatchPredictionResponse(BaseModel):
    results: list[PredictionResponse]


class RawAnalyzeRequest(BaseModel):
    payload: dict[str, Any]
    source: Literal["auto", "wazuh", "ecs"] = "auto"
    include_normalized: bool = False


class RawAnalyzeResponse(BaseModel):
    result: PredictionResponse
    normalized_event: dict[str, Any] | None = None


class WazuhBulkAnalyzeResponse(BaseModel):
    requested_count: int
    analyzed_count: int
    label_counts: dict[str, int]
    severity_counts: dict[str, int]
    average_risk_score: float
    high_risk_count: int
    top_samples: list[PredictionResponse] = Field(default_factory=list)


class WazuhDecisionLogEntry(BaseModel):
    timestamp: str | None = None
    event_id: str | None = None
    wazuh_rule_id: str | None = None
    wazuh_rule_description: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: str | int | None = None
    model_label: str
    model_confidence: float
    risk_score: float
    severity: str
    decision: Literal["blocked", "should_block", "monitor"]
    decision_reason: str
    response_command: str | None = None
    blocked_by_wazuh: bool = False
    block_event_id: str | None = None
    block_event_timestamp: str | None = None
    block_event_rule_id: str | None = None
    summary: str
    full_log: str | None = None


class WazuhDecisionBoardResponse(BaseModel):
    requested_count: int
    analyzed_count: int
    blocked_count: int
    should_block_count: int
    monitor_count: int
    rows: list[WazuhDecisionLogEntry] = Field(default_factory=list)


class WebhookIngestResponse(BaseModel):
    status: str
    ingestion_id: str
    source: Literal["wazuh", "ecs"]
    processed_at: str
    result: PredictionResponse
    normalized_event: dict[str, Any] | None = None


class WazuhBlockRequest(BaseModel):
    command: str = "firewall-drop"
    srcip: str
    timeout: int = 600
    reason: str


class WazuhDecisionResponse(BaseModel):
    status: str
    ingestion_id: str
    source: Literal["wazuh"]
    processed_at: str
    should_block: bool
    decision_reason: str
    source_ip: str | None = None
    result: PredictionResponse
    wazuh_block_request: WazuhBlockRequest | None = None
    normalized_event: dict[str, Any] | None = None


class WebhookEventSummary(BaseModel):
    ingestion_id: str
    source: Literal["wazuh", "ecs"]
    processed_at: str
    label: str
    confidence: float
    risk_score: float
    severity: str
    srcip: str | None = None
    destip: str | None = None
    destport: str | int | None = None
    active_response_enabled: bool


class StoredWebhookEvent(BaseModel):
    ingestion_id: str
    source: Literal["wazuh", "ecs"]
    processed_at: str
    result: PredictionResponse
    normalized_event: dict[str, Any]
    raw_payload: dict[str, Any]


class DemoEvent(BaseModel):
    name: str
    description: str
    event: dict[str, Any]


class RawDemoEvent(BaseModel):
    name: str
    source: Literal["wazuh", "ecs"]
    payload: dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    app: str
