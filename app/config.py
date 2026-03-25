import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
STATIC_DIR = BASE_DIR / "app" / "static"
MODEL_PATH = MODELS_DIR / "automatic_soc_demo_model.pkl"
SAMPLE_EVENTS_PATH = DATA_DIR / "sample_events.json"
SAMPLE_RAW_EVENTS_PATH = DATA_DIR / "sample_raw_events.json"
WEBHOOK_DB_PATH = Path(os.getenv("AUTOMATICSOC_DB_PATH", str(DATA_DIR / "automaticsoc.db"))).expanduser()

APP_NAME = "AutomaticSOC"
APP_DESCRIPTION = "AI-assisted autonomous SOC demo with Random Forest detection"

WEBHOOK_TOKEN = os.getenv("AUTOMATICSOC_WEBHOOK_TOKEN", "").strip() or None
try:
    WEBHOOK_HISTORY_SIZE = max(int(os.getenv("AUTOMATICSOC_WEBHOOK_HISTORY_SIZE", "250")), 20)
except ValueError:
    WEBHOOK_HISTORY_SIZE = 250
