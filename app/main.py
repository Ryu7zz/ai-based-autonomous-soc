from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import (
    APP_DESCRIPTION,
    APP_NAME,
    SAMPLE_EVENTS_PATH,
    SAMPLE_RAW_EVENTS_PATH,
    STATIC_DIR,
    WEBHOOK_TOKEN,
)
from app.schemas import (
    BatchPredictionResponse,
    CICIDSTrainRequest,
    DemoEvent,
    HealthResponse,
    ModelInfo,
    PredictionResponse,
    RawDemoEvent,
    RawAnalyzeRequest,
    RawAnalyzeResponse,
    SecurityEvent,
    StoredWebhookEvent,
    WazuhDecisionResponse,
    WazuhDecisionBoardResponse,
    TrainRequest,
    WazuhBulkAnalyzeRequest,
    WazuhBulkAnalyzeResponse,
    WazuhTrainRequest,
    WebhookEventSummary,
    WebhookIngestResponse,
)
from app.service import DetectionService


@lru_cache
def get_service() -> DetectionService:
    return DetectionService()


app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _verify_webhook_token(incoming_token: str | None) -> None:
    if WEBHOOK_TOKEN and incoming_token != WEBHOOK_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid webhook token")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", app=APP_NAME)


@app.get("/api/model", response_model=ModelInfo)
def model_info(service: DetectionService = Depends(get_service)) -> ModelInfo:
    return service.model_info()


@app.post("/api/train/demo", response_model=ModelInfo)
def train_demo(
    request: TrainRequest,
    service: DetectionService = Depends(get_service),
) -> ModelInfo:
    return service.retrain_demo_model(samples=request.samples, seed=request.seed)


@app.post("/api/train/wazuh", response_model=ModelInfo)
def train_from_wazuh(
    request: WazuhTrainRequest,
    service: DetectionService = Depends(get_service),
) -> ModelInfo:
    try:
        return service.retrain_from_wazuh(
            limit=request.limit,
            time_range=request.time_range,
            seed=request.seed,
        )
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/analyze/wazuh/bulk", response_model=WazuhBulkAnalyzeResponse)
def analyze_wazuh_bulk(
    request: WazuhBulkAnalyzeRequest,
    service: DetectionService = Depends(get_service),
) -> WazuhBulkAnalyzeResponse:
    try:
        return service.analyze_wazuh_bulk(
            target_count=request.target_count,
            batch_size=request.batch_size,
            time_range=request.time_range,
            include_samples=request.include_samples,
            sample_size=request.sample_size,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/wazuh/ai/decision", response_model=WazuhDecisionResponse)
def wazuh_ai_decision(
    payload: dict[str, Any],
    include_normalized: bool = False,
    x_webhook_token: str | None = Header(default=None, alias="X-Webhook-Token"),
    service: DetectionService = Depends(get_service),
) -> WazuhDecisionResponse:
    _verify_webhook_token(x_webhook_token)
    try:
        return service.decide_wazuh_event(
            payload=payload,
            include_normalized=include_normalized,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/wazuh/decision-board", response_model=WazuhDecisionBoardResponse)
def wazuh_decision_board(
    limit: int = 200,
    time_range: str = "24h",
    service: DetectionService = Depends(get_service),
) -> WazuhDecisionBoardResponse:
    try:
        return service.wazuh_decision_board(limit=limit, time_range=time_range)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/train/cicids", response_model=ModelInfo)
def train_cicids(
    request: CICIDSTrainRequest,
    service: DetectionService = Depends(get_service),
) -> ModelInfo:
    csv_path = Path(request.csv_path).expanduser()
    try:
        return service.retrain_from_cicids(
            csv_path=csv_path,
            max_rows=request.max_rows,
            normal_ratio=request.normal_ratio,
            seed=request.seed,
        )
    except (FileNotFoundError, ValueError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/analyze", response_model=PredictionResponse)
def analyze(
    event: SecurityEvent,
    service: DetectionService = Depends(get_service),
) -> PredictionResponse:
    return service.analyze_event(event.model_dump(mode="python", exclude_none=True))


@app.post("/api/analyze/raw", response_model=RawAnalyzeResponse)
def analyze_raw(
    request: RawAnalyzeRequest,
    service: DetectionService = Depends(get_service),
) -> RawAnalyzeResponse:
    try:
        result, normalized = service.analyze_raw_event(
            payload=request.payload,
            source=request.source,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return RawAnalyzeResponse(
        result=result,
        normalized_event=normalized if request.include_normalized else None,
    )


@app.post("/api/analyze/batch", response_model=BatchPredictionResponse)
def analyze_batch(
    events: list[SecurityEvent],
    service: DetectionService = Depends(get_service),
) -> BatchPredictionResponse:
    results = [
        service.analyze_event(event.model_dump(mode="python", exclude_none=True))
        for event in events
    ]
    return BatchPredictionResponse(results=results)


@app.post("/api/webhook/wazuh", response_model=WebhookIngestResponse)
def ingest_wazuh_webhook(
    payload: dict[str, Any],
    include_normalized: bool = False,
    x_webhook_token: str | None = Header(default=None, alias="X-Webhook-Token"),
    service: DetectionService = Depends(get_service),
) -> WebhookIngestResponse:
    _verify_webhook_token(x_webhook_token)
    try:
        result, normalized, ingestion_id, processed_at = service.ingest_webhook_event(
            payload=payload,
            source="wazuh",
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return WebhookIngestResponse(
        status="processed",
        ingestion_id=ingestion_id,
        source="wazuh",
        processed_at=processed_at,
        result=result,
        normalized_event=normalized if include_normalized else None,
    )


@app.get("/api/webhook/events", response_model=list[WebhookEventSummary])
def webhook_events(
    limit: int = 20,
    service: DetectionService = Depends(get_service),
) -> list[WebhookEventSummary]:
    clipped_limit = max(min(limit, 200), 1)
    return service.recent_webhook_events(limit=clipped_limit)


@app.get("/api/webhook/events/{ingestion_id}", response_model=StoredWebhookEvent)
def webhook_event_detail(
    ingestion_id: str,
    service: DetectionService = Depends(get_service),
) -> StoredWebhookEvent:
    event = service.webhook_event_by_ingestion_id(ingestion_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Webhook event not found")
    return event


@app.get("/api/demo/events", response_model=list[DemoEvent])
def demo_events() -> list[DemoEvent]:
    with SAMPLE_EVENTS_PATH.open("r", encoding="utf-8") as file_pointer:
        payload = json.load(file_pointer)
    return [DemoEvent(**item) for item in payload]


@app.get("/api/demo/raw-events", response_model=list[RawDemoEvent])
def demo_raw_events() -> list[RawDemoEvent]:
    with SAMPLE_RAW_EVENTS_PATH.open("r", encoding="utf-8") as file_pointer:
        payload = json.load(file_pointer)
    return [RawDemoEvent(**item) for item in payload]
