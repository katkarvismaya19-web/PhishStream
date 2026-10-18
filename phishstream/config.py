import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("PHISH_DATA", ROOT / "data"))
ARTIFACTS = DATA / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

EVENTS_CSV = DATA / "urls.csv"            # unified dataset (synthetic or real)
BLOOM_PATH = ARTIFACTS / "bloom.bin"
MODEL_PATH = ARTIFACTS / "model.joblib"
INSIGHTS_PATH = ARTIFACTS / "insights.json"
METRICS_PATH = ARTIFACTS / "model_metrics.json"
BENCH_PATH = ARTIFACTS / "benchmarks.json"

BLOOM_FP = 0.001
DGIM_WINDOW = 10_000
WAVE_WINDOW = 1_000
WAVE_ALERT_RATIO = 0.25          # >25% of the last 1,000 events malicious -> campaign alert
MODEL_THRESHOLD = 0.5

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "url-events")
REDIS_URL = os.environ.get("REDIS_URL", "")
