# AutomaticSOC Architecture and Full Usage Guide

This guide explains the full architecture of your project in practical terms and gives exact steps to run, use, and demonstrate it.

## 1. What this system does

AutomaticSOC is an AI-assisted SOC pipeline that:

1. Pulls or receives logs from Wazuh.
2. Normalizes those logs to a common format.
3. Extracts security features.
4. Uses a Random Forest model to decide threat type and risk.
5. Decides response state per log:
   - `blocked`
   - `should_block`
   - `monitor`
6. Shows all of that in your web interface in a structured way.

## 2. High-level architecture

```text
Wazuh Manager / Wazuh API / Wazuh Webhook
                |
                v
        app/main.py (FastAPI routes)
                |
                v
      app/service.py (orchestration layer)
        |         |            |
        |         |            +--> app/storage.py (SQLite history)
        |         |
        |         +--> app/normalize.py (Wazuh/ECS -> common schema)
        |
        +--> app/features.py (feature engineering)
                |
                v
          app/model.py (Random Forest model)
                |
                v
         app/response.py (decision + response command)
                |
                v
   app/static/index.html + app/static/app.js + app/static/styles.css
```

## 3. Component-by-component explanation

## 3.1 API layer (FastAPI)

File: `app/main.py`

Main responsibilities:

- Expose training endpoints.
- Expose analysis endpoints.
- Expose webhook ingestion and history endpoints.
- Expose Wazuh decision-board endpoint for your dashboard.

Key endpoints:

- `GET /api/health`
- `GET /api/model`
- `POST /api/train/demo`
- `POST /api/train/cicids`
- `POST /api/train/wazuh`
- `POST /api/analyze`
- `POST /api/analyze/raw`
- `POST /api/analyze/batch`
- `POST /api/analyze/wazuh/bulk`
- `GET /api/wazuh/decision-board`
- `POST /api/webhook/wazuh`
- `GET /api/webhook/events`
- `GET /api/webhook/events/{ingestion_id}`

## 3.2 Orchestration layer

File: `app/service.py`

This is the core brain of the app. It:

- Loads and caches the Random Forest model.
- Trains from demo, CICIDS, or Wazuh data.
- Runs per-event analysis.
- Handles webhook ingestion + persistence.
- Builds the structured Wazuh decision board.

Important logic in the decision board flow:

1. Pull N recent alerts from Wazuh API.
2. Analyze each alert with the model.
3. Detect if that source IP already has real block evidence (Wazuh `firewall-drop` / rule `651`).
4. Assign final decision for each row:
   - `blocked`: real active response evidence found.
   - `should_block`: model says high risk and recommends blocking.
   - `monitor`: low/medium risk, no immediate block.

## 3.3 Normalization layer

File: `app/normalize.py`

Wazuh and ECS payloads have different field names. This layer converts them into one schema:

- `srcip`, `destip`, `destport`
- `rule.level`, `rule.description`, `rule.id`
- `auth.failures`
- `network.bytes`, `network.packets`, `network.duration`
- and other fields used by feature extraction

Why this matters: the model can only work reliably if inputs are consistent.

## 3.4 Feature extraction

File: `app/features.py`

Converts normalized security event into numeric model features (for example severity, traffic rate, auth failure signals, reconnaissance/malware hints).

These features are passed into Random Forest exactly in the trained feature order.

## 3.5 ML model

File: `app/model.py`

- Model type: `RandomForestClassifier`
- Supports training from:
  - synthetic demo data
  - CICIDS CSV data
  - streamed Wazuh alerts
- Model artifact is saved under `models/`.

## 3.6 Response planner

File: `app/response.py`

Turns model output into operational guidance:

- severity level
- recommended actions
- whether active response is enabled
- candidate command (for example iptables drop)

## 3.7 Persistence

File: `app/storage.py`

Stores webhook events in SQLite so event history remains available after restart.

Default DB path:

- `data/automaticsoc.db`

Configurable by:

- `AUTOMATICSOC_DB_PATH`

## 3.8 Web UI

Files:

- `app/static/index.html`
- `app/static/app.js`
- `app/static/styles.css`

Main screens/functions:

- model metrics
- manual JSON analyzer
- training controls
- Wazuh bulk analysis summary
- structured Wazuh decision board table

The decision board table shows per log:

- time
- Wazuh rule info
- source/destination
- AI label + confidence + risk
- final decision (`blocked`, `should_block`, `monitor`)
- how it was blocked (real evidence when present)

## 4. End-to-end data flow (real Wazuh scenario)

## 4.1 Detection path

1. Wazuh records an event (for example failed SSH logins).
2. App reads event from Wazuh API or receives it by webhook.
3. App normalizes payload.
4. App extracts features.
5. Random Forest predicts label + confidence.
6. App computes risk score and response recommendation.
7. UI shows the result.

## 4.2 Blocking evidence path

1. Wazuh active response triggers `firewall-drop`.
2. Wazuh produces active-response evidence (rule `651` type events).
3. Decision-board correlation maps that evidence by `srcip`.
4. UI marks related rows as `blocked` and shows block context.

## 5. Setup guide (from zero)

## 5.1 Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 5.2 Wazuh connection configuration

```bash
export WAZUH_API_URL="https://<wazuh-ip>:55000"
export WAZUH_API_TOKEN="<your-bearer-token>"
export WAZUH_API_VERIFY_SSL="false"
```

If API access fails or you want direct local ingestion from Wazuh logs, enable file mode:

```bash
export WAZUH_SOURCE_MODE="file"
export WAZUH_ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
```

Hybrid fallback mode (recommended):

```bash
export WAZUH_SOURCE_MODE="auto"
```

In `auto`, app tries Wazuh API first, then falls back to the local alerts file.

If your Wazuh instance uses username/password auth flow, use this instead:

```bash
export WAZUH_API_USER="admin"
export WAZUH_API_PASSWORD="<your-password>"
```

Optional app security/config:

```bash
export AUTOMATICSOC_WEBHOOK_TOKEN="replace-with-strong-token"
export AUTOMATICSOC_DB_PATH="$(pwd)/data/automaticsoc.db"
export AUTOMATICSOC_WEBHOOK_HISTORY_SIZE="500"
export WAZUH_MAX_BULK_ANALYSIS="300000"
```

## 5.3 Start the app

```bash
uvicorn app.main:app --reload
```

Open:

- `http://127.0.0.1:8000`

## 6. How to use the system (operator guide)

## 6.1 First run checklist

1. Open dashboard and verify model card loads.
2. Click `Retrain Demo Model` once (optional warm-up).
3. Set Wazuh credentials correctly in environment.

## 6.2 Train from real Wazuh logs

From UI:

- Set Wazuh train limit and click `Retrain From Wazuh`.

From API:

```bash
curl -X POST http://127.0.0.1:8000/api/train/wazuh \
  -H "Content-Type: application/json" \
  -d '{"limit": 100000, "time_range": "30d", "seed": 7}'
```

## 6.3 Run large bulk analysis

From UI:

- Set bulk count and click `Run Wazuh Bulk Analysis`.

From API:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze/wazuh/bulk \
  -H "Content-Type: application/json" \
  -d '{"target_count": 100000, "batch_size": 5000, "time_range": "30d", "include_samples": true, "sample_size": 20}'
```

## 6.4 Use structured Wazuh decision board

From UI:

1. Go to `Structured Wazuh log decision dashboard` section.
2. Set log count and time range.
3. Click `Refresh Wazuh Logs`.

From API:

```bash
curl "http://127.0.0.1:8000/api/wazuh/decision-board?limit=200&time_range=24h"
```

Read response fields:

- `blocked_count`: logs with real block evidence.
- `should_block_count`: AI says block should be executed.
- `monitor_count`: keep tracking, no immediate block.
- `rows[]`: full per-log structured detail.

## 6.5 Webhook ingestion mode

If you push alerts to app instead of pulling from Wazuh API:

```bash
curl -X POST "http://127.0.0.1:8000/api/webhook/wazuh?include_normalized=true" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: replace-with-strong-token" \
  -d @wazuh-alert.json
```

History:

```bash
curl "http://127.0.0.1:8000/api/webhook/events?limit=20"
curl "http://127.0.0.1:8000/api/webhook/events/<ingestion_id>"
```

## 7. How AI decides block or not

Your app does not randomly block. Decision is derived from:

1. Model label and confidence.
2. Engineered risk score.
3. Response policy threshold in response planner.
4. Real Wazuh active-response evidence correlation.

Decision semantics:

- `blocked`: Wazuh already blocked the source (evidence found).
- `should_block`: AI strongly recommends block, but evidence not yet seen.
- `monitor`: event is not severe enough for block.

## 8. Demo/presentation script

Use this exact story:

1. Show dashboard metrics and model info.
2. Refresh decision board to show real Wazuh logs in table format.
3. Open rows with `blocked` state and point to `How blocked` and source IP.
4. Show Wazuh-side evidence from your runbook in `artifacts/pptx/13_real_wazuh_logs_and_blocking_runbook.md`.
5. Show bulk analysis and 100k capability.

## 9. Troubleshooting

## 9.1 Wazuh board not loading

- Check `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`.
- If using self-signed cert, keep `WAZUH_API_VERIFY_SSL=false`.
- Verify manager/dashboard API port is reachable.
- If API is unstable, switch to `WAZUH_SOURCE_MODE=file`.
- Ensure app user can read `/var/ossec/logs/alerts/alerts.json`.

Permission fix example (run once):

```bash
sudo setfacl -m u:$USER:rx /var/ossec/logs
sudo setfacl -m u:$USER:rx /var/ossec/logs/alerts
sudo setfacl -m u:$USER:r /var/ossec/logs/alerts/alerts.json
sudo setfacl -d -m u:$USER:rx /var/ossec/logs/alerts
```

## 9.2 No `blocked` rows

- Active response may not be configured/enabled in Wazuh.
- No `firewall-drop` / rule `651` evidence in recent window.
- Increase `time_range` in decision board.

## 9.3 Only monitor rows

- Current alerts may genuinely be low risk.
- Train model with larger/more representative Wazuh or CICIDS data.
- Verify normalization fields (srcip, rule level, auth failures) exist in incoming logs.

## 10. Developer quick verification

Run tests:

```bash
PYTHONPATH=$(pwd) .venv/bin/pytest tests -q
```

Expected: all tests pass.
