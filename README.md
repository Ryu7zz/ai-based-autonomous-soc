# AutomaticSOC

AutomaticSOC is a runnable MVP for your team's "AI-powered Autonomous SOC" project. It turns SOC-style JSON alerts into engineered features, classifies them with a Random Forest model, and recommends automated response actions that mirror a Wazuh Active Response workflow.

## What this project includes

- FastAPI backend for health, model info, training, and alert analysis
- Demo dashboard for presenting the pipeline interactively
- JSON feature extraction inspired by Wazuh / ECS-style events
- Raw event normalization (`Wazuh` and `ECS`) through `POST /api/analyze/raw`
- Direct Wazuh webhook ingestion through `POST /api/webhook/wazuh`
- Persistent webhook storage in SQLite for restart-safe event history
- Random Forest training pipeline with synthetic data or real CIC-IDS CSV files
- Automated response recommendations for brute force, DDoS, malware, and port scan activity
- Sample events and tests for a clean demo story

## Architecture

1. Log source sends a JSON event that looks like a Wazuh / SIEM alert.
2. `app/features.py` extracts numeric security features from the event.
3. `app/model.py` loads or trains a Random Forest classifier.
4. `app/service.py` predicts the threat label and calculates a risk score.
5. `app/response.py` generates analyst guidance and an Active Response-style command.
6. The dashboard or API returns the result for monitoring and presentation.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

The model is trained automatically the first time the service needs it. You can also train it manually:

```bash
python scripts/train_demo_model.py
```

To train from CIC-IDS data:

```bash
python scripts/train_from_cicids.py /path/to/CICIDS.csv --max-rows 250000
```

## Example API usage

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "srcip": "185.44.9.10",
    "destip": "10.0.0.15",
    "destport": 22,
    "protocol": "tcp",
    "rule": {
      "level": 12,
      "description": "Multiple authentication failures detected"
    },
    "network": {
      "bytes": 12400,
      "packets": 155,
      "duration": 18
    },
    "auth": {
      "failures": 21
    }
  }'
```

## Useful commands

```bash
python scripts/train_demo_model.py
python scripts/train_from_cicids.py /path/to/CICIDS.csv --max-rows 250000
python scripts/simulate_events.py
pytest
```

## Raw Wazuh / ECS ingestion

Use `GET /api/demo/raw-events` for ready-to-use payloads (`wazuh` and `ecs`).

```bash
curl -X POST http://127.0.0.1:8000/api/analyze/raw \
  -H "Content-Type: application/json" \
  -d '{
    "source": "wazuh",
    "include_normalized": true,
    "payload": {
      "rule": {
        "level": 12,
        "description": "Multiple authentication failures",
        "firedtimes": 14
      },
      "data": {
        "srcip": "185.44.9.10",
        "dstip": "10.0.0.15",
        "dstport": "22",
        "proto": "tcp",
        "bytes": "15422",
        "packets": "172",
        "duration": "20",
        "failed_attempts": "22"
      }
    }
  }'
```

```bash
curl -X POST http://127.0.0.1:8000/api/train/cicids \
  -H "Content-Type: application/json" \
  -d '{
    "csv_path": "/path/to/CICIDS2017.csv",
    "max_rows": 250000,
    "seed": 7
  }'
```

## Wazuh webhook integration

Send raw Wazuh alerts directly to the webhook endpoint:

```bash
curl -X POST "http://127.0.0.1:8000/api/webhook/wazuh?include_normalized=true" \
  -H "Content-Type: application/json" \
  -d @wazuh-alert.json
```

Optional shared-secret protection:

```bash
export AUTOMATICSOC_WEBHOOK_TOKEN="replace-with-strong-token"
uvicorn app.main:app --reload
```

Then send:

```bash
curl -X POST "http://127.0.0.1:8000/api/webhook/wazuh" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: replace-with-strong-token" \
  -d @wazuh-alert.json
```

Check recent webhook processing history:

```bash
curl "http://127.0.0.1:8000/api/webhook/events?limit=20"
```

Get full stored event details:

```bash
curl "http://127.0.0.1:8000/api/webhook/events/<ingestion_id>"
```

SQLite persistence config (defaults to `data/automaticsoc.db`):

```bash
export AUTOMATICSOC_DB_PATH="/absolute/path/to/automaticsoc.db"
export AUTOMATICSOC_WEBHOOK_HISTORY_SIZE="500"
uvicorn app.main:app --reload
```

## Project structure

```text
app/
  main.py          FastAPI entrypoint
  service.py       Detection orchestration
  storage.py       SQLite webhook persistence
  model.py         Demo + CIC-IDS training and preprocessing
  normalize.py     Raw Wazuh / ECS normalization
  features.py      JSON -> feature extraction
  response.py      Automated response plan generation
  schemas.py       API request / response models
  static/          Dashboard assets
data/
  sample_events.json
  sample_raw_events.json
scripts/
  train_demo_model.py
  train_from_cicids.py
  simulate_events.py
tests/
  test_cicids_training.py
  test_features.py
  test_normalize.py
  test_persistence.py
  test_service.py
  test_webhook.py
```

## Next steps for the team

- Connect your Wazuh webhook or Logstash output to `POST /api/analyze/raw`
- Point `POST /api/train/cicids` to your cleaned CIC-IDS2017 datasets
- Add analyst feedback storage for continuous retraining
- Push the active-response command into a real Wazuh integration script
