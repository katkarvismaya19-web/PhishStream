"""
The streaming engine: every URL event passes through
  1. Bloom filter        -> known phishing (two-stage: confirmed against the exact store)
  2. ML model            -> zero-day phishing not on any list
  3. DGIM                -> malicious events in the last N events (campaign / wave alert)
  4. HyperLogLog         -> distinct hosts and distinct malicious hosts seen
  5. Count-Min Sketch    -> top targeted brands and top malicious hosts (heavy hitters)
  6. Reservoir sample    -> uniform sample of flagged events for analysts
Exact counters run alongside ONLY to measure sketch accuracy; they are not needed in production.
The same class runs in-process (local mode / Render) and inside Spark foreachBatch (cluster mode).
"""
import time
from collections import Counter, deque

import joblib
import numpy as np

from phishstream import config
from phishstream.features.url_features import brand_of, explain, extract, split
from phishstream.sketches.bloom import BloomFilter
from phishstream.sketches.countmin import CountMinSketch
from phishstream.sketches.dgim import DGIM
from phishstream.sketches.hyperloglog import HyperLogLog
from phishstream.sketches.reservoir import Reservoir


def normalize(url: str) -> str:
    u, host, path, query, _ = split(url)
    host = host[4:] if host.startswith("www.") else host
    return host + path.rstrip("/") + ("?" + query if query else "")


class Engine:
    def __init__(self, bloom: BloomFilter, model_bundle, exact_store: set | None = None, track_exact=True):
        self.bloom, self.exact = bloom, exact_store
        self.model = model_bundle["model"]
        self.thr = model_bundle.get("threshold", config.MODEL_THRESHOLD)
        self.dgim = DGIM(config.DGIM_WINDOW)
        self.hll_all, self.hll_bad = HyperLogLog(12), HyperLogLog(12)
        self.cms_brand, self.cms_host = CountMinSketch(0.001, 0.01, 12), CountMinSketch(0.0005, 0.01, 12)
        self.sample = Reservoir(40)
        self.recent = deque(maxlen=60)
        self.timeline = deque(maxlen=600)
        self.n = 0
        self.c = Counter()
        self.track_exact = track_exact
        self.exact_window = deque(maxlen=config.DGIM_WINDOW)
        self.exact_hosts, self.exact_bad_hosts, self.exact_brand = set(), set(), Counter()
        self.started = time.time()

    @classmethod
    def from_artifacts(cls, with_exact_store=True):
        bloom = BloomFilter.from_bytes(config.BLOOM_PATH.read_bytes())
        exact = None
        if with_exact_store and (config.ARTIFACTS / "blacklist.txt").exists():
            exact = set((config.ARTIFACTS / "blacklist.txt").read_text().split("\n"))
        return cls(bloom, joblib.load(config.MODEL_PATH), exact)

    # ------------------------------------------------------------------
    def score(self, urls: list[str]) -> np.ndarray:
        return self.model.predict_proba(np.array([extract(u) for u in urls], dtype=np.float32))[:, 1]

    def classify(self, url: str, p: float | None = None) -> dict:
        key = normalize(url)
        in_bloom = key in self.bloom
        known = in_bloom and (self.exact is None or key in self.exact)
        if p is None:
            p = float(self.score([url])[0])
        verdict = "known_phishing" if known else ("likely_phishing" if p >= self.thr else "clean")
        return {"url": url, "verdict": verdict, "score": round(float(p), 4), "in_bloom": in_bloom,
                "bloom_false_positive": in_bloom and not known, "reasons": explain(url) if verdict != "clean" or p > 0.3 else []}

    def process_batch(self, urls: list[str], truth: list[int] | None = None) -> list[dict]:
        ps = self.score(urls)
        out = []
        for i, (u, p) in enumerate(zip(urls, ps)):
            r = self.classify(u, p)
            self._update(r, None if truth is None else truth[i])
            out.append(r)
        return out

    def _update(self, r, truth):
        self.n += 1
        bad = r["verdict"] != "clean"
        host = split(r["url"])[1]
        self.c[r["verdict"]] += 1
        if r["bloom_false_positive"]:
            self.c["bloom_fp_caught"] += 1
        if truth is not None:
            self.c["tp" if bad and truth else "fp" if bad else "fn" if truth else "tn"] += 1
        self.dgim.add(int(bad))
        self.hll_all.add(host)
        if bad:
            self.hll_bad.add(host)
            self.cms_host.add(host)
            b = brand_of(host) or brand_of(r["url"])
            if b:
                self.cms_brand.add(b)
                if self.track_exact:
                    self.exact_brand[b] += 1
            self.sample.add({k: r[k] for k in ("url", "verdict", "score")})
            self.recent.appendleft({k: r[k] for k in ("url", "verdict", "score")})
        if self.track_exact:
            self.exact_window.append(int(bad))
            self.exact_hosts.add(host)
            if bad:
                self.exact_bad_hosts.add(host)
        if self.n % 50 == 0:
            self.timeline.append({"n": self.n, "est": self.dgim.count(config.WAVE_WINDOW),
                                  "exact": sum(list(self.exact_window)[-config.WAVE_WINDOW:]) if self.track_exact else None})

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        w = config.WAVE_WINDOW
        est_w = self.dgim.count(w)
        ratio = est_w / min(w, max(self.n, 1))
        level = "alert" if ratio >= config.WAVE_ALERT_RATIO else "elevated" if ratio >= config.WAVE_ALERT_RATIO / 2 else "normal"
        exact_w = sum(list(self.exact_window)[-w:]) if self.track_exact else None
        c = self.c
        prec = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
        rec = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
        return {
            "events": self.n, "uptime_s": round(time.time() - self.started),
            "verdicts": {k: c[k] for k in ("known_phishing", "likely_phishing", "clean")},
            "bloom_fp_caught": c["bloom_fp_caught"],
            "live_precision": None if prec is None else round(prec, 4),
            "live_recall": None if rec is None else round(rec, 4),
            "wave": {"level": level, "malicious_last_window": est_w, "window": w, "ratio": round(ratio, 3)},
            "dgim": {"N": self.dgim.N, "buckets": len(self.dgim.buckets), "est_N": self.dgim.count(),
                     "exact_N": sum(self.exact_window) if self.track_exact else None, "est_w": est_w, "exact_w": exact_w,
                     "bucket_sizes": [b["size"] for b in self.dgim.snapshot()][:40]},
            "hll": {"distinct_hosts": self.hll_all.count(), "distinct_bad_hosts": self.hll_bad.count(),
                    "exact_hosts": len(self.exact_hosts) if self.track_exact else None,
                    "exact_bad_hosts": len(self.exact_bad_hosts) if self.track_exact else None,
                    "bytes": self.hll_all.nbytes()},
            "cms": {"top_brands": self.cms_brand.top(10), "top_hosts": self.cms_host.top(8),
                    "exact_top_brands": self.exact_brand.most_common(10) if self.track_exact else None,
                    "bytes": self.cms_brand.nbytes()},
            "bloom": {"items": self.bloom.count, "bytes": self.bloom.nbytes(), "k": self.bloom.k,
                      "expected_fp": round(self.bloom.expected_fp(), 5)},
            "recent": list(self.recent)[:15], "sample": self.sample.items[:15],
            "timeline": list(self.timeline)[-300:],
        }
