"""
FastAPI service: URL check API, live stream dashboard (WebSocket), analytics insights.
  local mode   (default): in-process engine fed by the event simulator - runs anywhere, incl. Render
  cluster mode (REDIS_URL set): live stats come from the Spark Structured Streaming job via Redis
Run: uvicorn phishstream.api.app:app --port 8000
"""
import asyncio
import json
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishstream import config

STATIC = Path(__file__).parent / "static"
state = {"engine": None, "source": None, "rate": int(os.environ.get("SIM_RATE", "400")), "running": True,
         "redis": None, "lock": threading.Lock()}


def ensure_artifacts():
    if not (config.BLOOM_PATH.exists() and config.MODEL_PATH.exists() and config.INSIGHTS_PATH.exists()):
        from phishstream import pipeline
        import sys
        sys.argv = ["pipeline"]
        pipeline.main()


def simulator_loop():
    """Feeds the engine in small batches at the configured rate (local mode)."""
    while True:
        if not state["running"] or state["redis"]:
            time.sleep(0.5); continue
        t0 = time.time()
        n = max(1, state["rate"] // 10)
        urls, truth = state["source"].batch(n)
        with state["lock"]:
            state["engine"].process_batch(urls, truth)
        time.sleep(max(0.0, 0.1 - (time.time() - t0)))


@asynccontextmanager
async def lifespan(app):
    ensure_artifacts()
    from phishstream.stream.engine import Engine
    from phishstream.stream.simulator import EventSource
    state["engine"] = Engine.from_artifacts()
    state["source"] = EventSource()
    if config.REDIS_URL:
        import redis
        state["redis"] = redis.from_url(config.REDIS_URL)
    threading.Thread(target=simulator_loop, daemon=True).start()
    yield


app = FastAPI(title="PhishStream", version="1.0", lifespan=lifespan,
              description="Real-time phishing detection: Bloom filter + ML + streaming sketches")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class CheckIn(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, examples=["http://sbi-kyc-update12.xyz/login"])


def snapshot():
    if state["redis"]:
        raw = state["redis"].get("phishstream:snapshot")
        if raw:
            s = json.loads(raw); s["mode"] = "cluster (Kafka + Spark)"; return s
    with state["lock"]:
        s = state["engine"].snapshot()
    s["mode"] = "local simulator"; s["rate"] = state["rate"]; s["running"] = state["running"]
    return s


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "events": state["engine"].n}


@app.post("/api/check")
def check(body: CheckIn):
    with state["lock"]:
        r = state["engine"].classify(body.url)
        state["engine"]._update(r, None)
    return r


@app.get("/api/sample")
def sample():
    """A random URL from the threat list, for the 'known threat' demo button."""
    return {"url": state["source"].rng.choice(state["source"].known)}


@app.get("/api/live")
def live():
    return snapshot()


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await ws.send_text(json.dumps(snapshot(), default=str))
            await asyncio.sleep(1)
    except (WebSocketDisconnect, RuntimeError):
        pass


class SimIn(BaseModel):
    rate: int | None = Field(None, ge=0, le=5000)
    running: bool | None = None


@app.post("/api/sim")
def sim(body: SimIn):
    if body.rate is not None:
        state["rate"] = body.rate
    if body.running is not None:
        state["running"] = body.running
    return {"rate": state["rate"], "running": state["running"]}


@app.post("/api/burst")
def burst():
    if state["redis"]:
        raise HTTPException(409, "Bursts are triggered by the Kafka producer in cluster mode")
    state["source"].burst(max(600, state["rate"] * 8))
    return {"burst": True}


@app.get("/api/insights")
def insights():
    out = {"insights": json.loads(config.INSIGHTS_PATH.read_text())}
    for key, path in [("model", config.METRICS_PATH), ("benchmarks", config.BENCH_PATH),
                      ("spark", config.ARTIFACTS / "spark_results.json")]:
        out[key] = json.loads(path.read_text()) if path.exists() else None
    return out
