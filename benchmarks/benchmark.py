"""
Benchmarks every component against an exact baseline and writes data/artifacts/benchmarks.json.
  python -m benchmarks.benchmark
"""
import json
import platform
import random
import time
import tracemalloc
from collections import Counter, deque

import numpy as np

from phishstream import config
from phishstream.sketches.bloom import BloomFilter
from phishstream.sketches.countmin import CountMinSketch
from phishstream.sketches.dgim import DGIM
from phishstream.sketches.hyperloglog import HyperLogLog


def mem(fn):
    tracemalloc.start()
    obj = fn()
    cur, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return obj, cur


def bench_engine(n_events=60_000):
    from phishstream.stream.engine import Engine
    from phishstream.stream.simulator import EventSource
    eng, src = Engine.from_artifacts(), EventSource(seed=3)
    batches = [src.batch(500) for _ in range(n_events // 500)]
    t0 = time.time()
    for urls, truth in batches:
        eng.process_batch(urls, truth)
    secs = time.time() - t0
    lat = []
    for u in batches[0][0][:2000]:
        t = time.perf_counter(); eng.classify(u); lat.append((time.perf_counter() - t) * 1000)
    s = eng.snapshot()
    return {"events": n_events, "seconds": round(secs, 2), "events_per_sec_single_core": int(n_events / secs),
            "p50_ms": round(float(np.percentile(lat, 50)), 3), "p95_ms": round(float(np.percentile(lat, 95)), 3),
            "p99_ms": round(float(np.percentile(lat, 99)), 3),
            "live_precision": s["live_precision"], "live_recall": s["live_recall"]}


def bench_bloom():
    keys = (config.ARTIFACTS / "blacklist.txt").read_text().split("\n")
    bf = BloomFilter.from_bytes(config.BLOOM_PATH.read_bytes())
    _, set_bytes = mem(lambda: set(keys))
    probes = [f"probe{random.random()}.example/{i}" for i in range(200_000)]
    fp = sum(p in bf for p in probes) / len(probes)
    t0 = time.time()
    b2 = BloomFilter(bf.m, bf.k)
    for k in keys:
        b2.add(k)
    build = time.time() - t0
    return {"items": len(keys), "bloom_bytes": bf.nbytes(), "python_set_bytes": set_bytes,
            "memory_ratio": round(set_bytes / bf.nbytes(), 1), "k": bf.k,
            "target_fp": config.BLOOM_FP, "expected_fp": round(bf.expected_fp(), 5), "observed_fp": round(fp, 5),
            "false_negatives": sum(k not in bf for k in keys), "build_urls_per_sec": int(len(keys) / build)}


def bench_hll():
    out = []
    for n in (10_000, 100_000, 1_000_000):
        h = HyperLogLog(12)
        for i in range(n):
            h.add(f"host-{i}.example")
        est = h.count()
        out.append({"true": n, "estimate": est, "error_pct": round(abs(est - n) / n * 100, 2)})
    _, set_bytes = mem(lambda: {f"host-{i}.example" for i in range(1_000_000)})
    return {"register_bytes": 4096, "theoretical_std_error_pct": round(1.04 / 64 * 100, 2), "runs": out,
            "exact_set_bytes_1M": set_bytes}


def bench_cms(n=1_000_000, keys=50_000):
    rng = np.random.default_rng(0)
    stream = rng.zipf(1.3, n) % keys
    cms, exact = CountMinSketch(0.001, 0.01, 20), Counter()
    for x in stream:
        k = f"k{x}"
        cms.add(k); exact[k] += 1
    top = exact.most_common(20)
    errs = [abs(cms.estimate(k) - c) / c * 100 for k, c in top]
    found = len({k for k, _ in cms.top(20)} & {k for k, _ in top})
    return {"events": n, "distinct_keys": len(exact), "sketch_bytes": cms.nbytes(), "width": cms.w, "depth": cms.d,
            "top20_mean_error_pct": round(float(np.mean(errs)), 3), "top20_recall": found / 20,
            "error_bound_eps_N": int(0.001 * n)}


def bench_dgim(n=1_000_000, window=10_000):
    rng = random.Random(1)
    d, exact, errs = DGIM(window), deque(maxlen=window), []
    p = 0.05
    for t in range(n):
        if t % 100_000 == 0:
            p = rng.choice([0.02, 0.05, 0.3, 0.6])
        bit = int(rng.random() < p)
        d.add(bit); exact.append(bit)
        if t % 1000 == 0 and t > window:
            a = sum(exact)
            if a:
                errs.append(abs(d.count() - a) / a * 100)
    return {"bits": n, "window": window, "buckets": len(d.buckets), "bucket_bytes": len(d.buckets) * 8,
            "exact_bytes": window // 8, "mean_error_pct": round(float(np.mean(errs)), 2),
            "max_error_pct": round(float(np.max(errs)), 2), "bound_pct": 50}


def main():
    res = {"machine": f"{platform.processor() or platform.machine()} / Python {platform.python_version()}"}
    for name, fn in [("engine", bench_engine), ("bloom", bench_bloom), ("hyperloglog", bench_hll),
                     ("countmin", bench_cms), ("dgim", bench_dgim)]:
        t0 = time.time()
        res[name] = fn()
        print(f"{name:12s} {time.time() - t0:5.1f}s  {res[name]}")
    config.BENCH_PATH.write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
