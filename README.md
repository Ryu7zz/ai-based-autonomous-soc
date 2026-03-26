# AutomaticSOC

AutomaticSOC is a runnable MVP for your team's "AI-powered Autonomous SOC" project. It turns SOC-style JSON alerts into engineered features, classifies them with a Random Forest model, and recommends automated response actions that mirror a Wazuh Active Response workflow.

For a full architecture walkthrough and operator guide, read `ARCHITECTURE_AND_USAGE_GUIDE.md`.

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

For live Wazuh integration, configure API credentials before starting the app:

```bash
export WAZUH_API_URL="https://<wazuh-manager-or-dashboard-ip>:55000"
export WAZUH_API_TOKEN="<your-bearer-token>"
export WAZUH_API_VERIFY_SSL="false"
```

If your Wazuh setup uses username/password login instead of direct token, use:

```bash
export WAZUH_API_USER="admin"
export WAZUH_API_PASSWORD="<your-password>"
```

If API access keeps failing, ingest directly from local Wazuh logs:

```bash
export WAZUH_SOURCE_MODE="file"
export WAZUH_ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
```

Recommended resilient mode:

```bash
export WAZUH_SOURCE_MODE="auto"
```

In `auto`, the app tries API first and automatically falls back to local alerts file.

If the app user cannot read Wazuh logs, grant access once:

```bash
sudo setfacl -m u:$USER:rx /var/ossec
sudo setfacl -m u:$USER:rx /var/ossec/logs
sudo setfacl -m u:$USER:rx /var/ossec/logs/alerts
sudo setfacl -m u:$USER:r /var/ossec/logs/alerts/alerts.json
sudo setfacl -d -m u:$USER:rx /var/ossec/logs/alerts
```

The model is trained automatically the first time the service needs it. You can also train it manually:

```bash
python scripts/train_demo_model.py
```

To train from CIC-IDS data:

```bash
python scripts/train_from_cicids.py /path/to/CICIDS.csv --max-rows 250000 --normal-ratio 0.8
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
python scripts/generate_wazuh_dashboard_ndjson.py
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

## AI-first decision flow for Wazuh blocking

If you want Wazuh to block only after Random Forest decision, use:

```bash
curl -X POST "http://127.0.0.1:8000/api/wazuh/ai/decision?include_normalized=true" \
  -H "Content-Type: application/json" \
  -d @wazuh-alert.json
```

Response semantics:

- `should_block: true` -> Wazuh should execute `wazuh_block_request` (for example `firewall-drop`).
- `should_block: false` -> Wazuh should keep monitoring and not block for this event.

This endpoint does not directly execute firewall actions; it returns AI decision and block request payload for Wazuh to execute.

## Full simulated attack run (safe lab)

Run all attack classes (Brute Force, Port Scan, DDoS, plus Normal) through AI-first flow:

```bash
PYTHONPATH=$(pwd) .venv/bin/python scripts/simulate_full_attack_flow.py --mode local
```

Against live running API:

```bash
PYTHONPATH=$(pwd) .venv/bin/python scripts/simulate_full_attack_flow.py --mode live --base-url http://127.0.0.1:8000
```

Report file is written to `artifacts/simulated_attack_report.json`.

SQLite persistence config (defaults to `data/automaticsoc.db`):

```bash
export AUTOMATICSOC_DB_PATH="/absolute/path/to/automaticsoc.db"
export AUTOMATICSOC_WEBHOOK_HISTORY_SIZE="500"
uvicorn app.main:app --reload
```

## Wazuh training and 100000+ alert analysis

Retrain from live Wazuh alerts (wide dataset):

```bash
curl -X POST http://127.0.0.1:8000/api/train/wazuh \
  -H "Content-Type: application/json" \
  -d '{
    "limit": 100000,
    "time_range": "30d",
    "seed": 7
  }'
```

Run large-scale bulk inference against Wazuh alerts:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze/wazuh/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "target_count": 100000,
    "batch_size": 5000,
    "time_range": "30d",
    "include_samples": true,
    "sample_size": 20
  }'
```

Optional upper bound for safety:

```bash
export WAZUH_MAX_BULK_ANALYSIS="300000"
```

## Custom Wazuh dashboard import

Generate saved objects:

```bash
python scripts/generate_wazuh_dashboard_ndjson.py
```

Then import `data/wazuh_dashboard_saved_objects.ndjson` in Wazuh Dashboard:

1. Open Dashboard Management -> Saved Objects -> Import.
2. Upload the file.
3. Open `AutomaticSOC Wazuh Operations Dashboard`.

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
  generate_wazuh_dashboard_ndjson.py
  simulate_events.py
tests/
  test_cicids_training.py
  test_features.py
  test_normalize.py
  test_persistence.py
  test_service.py
  test_wazuh_bulk.py
  test_webhook.py
```

## Next steps for the team

- Connect your Wazuh webhook or Logstash output to `POST /api/analyze/raw`
- Point `POST /api/train/cicids` to your cleaned CIC-IDS2017 datasets
- Add analyst feedback storage for continuous retraining
- Push the active-response command into a real Wazuh integration script
