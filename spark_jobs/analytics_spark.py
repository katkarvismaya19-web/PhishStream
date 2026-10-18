"""
Distributed analytics on Spark:
  1. SON algorithm  : frequent itemsets in 2 MapReduce passes (local Apriori per partition -> global count)
  2. PageRank       : iterative RDD PageRank with taxation on the domain-IP-network graph
  3. MLlib          : GBT classifier on lexical features with the same time-based split
Results are written to data/artifacts/spark_results.json and cross-checked against the
single-machine implementations.

spark-submit spark_jobs/analytics_spark.py [input_csv]
"""
import json
import sys
import time
from collections import Counter
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pyspark.ml.classification import GBTClassifier  # noqa: E402
from pyspark.ml.evaluation import BinaryClassificationEvaluator  # noqa: E402
from pyspark.ml.feature import VectorAssembler  # noqa: E402
from pyspark.sql import SparkSession, functions as F, types as T  # noqa: E402

from phishstream import config  # noqa: E402
from phishstream.analytics.frequent_itemsets import basket  # noqa: E402
from phishstream.features.url_features import FEATURE_NAMES, extract, registered_domain, split  # noqa: E402

MIN_SUP = 0.004


def son(spark, urls_rdd, n_total):
    """SON: pass 1 finds locally-frequent pairs per partition (scaled threshold) = candidates;
    pass 2 counts candidates exactly. No false negatives: a globally frequent set is frequent in >=1 partition."""
    baskets = urls_rdd.map(basket).filter(bool).cache()
    n = baskets.count()
    ms = max(2, int(MIN_SUP * n))
    parts = baskets.getNumPartitions()

    def local_apriori(it):
        bs = list(it)
        if not bs:
            return
        local_ms = max(1, ms * len(bs) / n)
        c1 = Counter(i for b in bs for i in b)
        f1 = {i for i, c in c1.items() if c >= local_ms}
        c2 = Counter(p for b in bs for p in combinations(sorted(i for i in b if i in f1), 2))
        for p, c in c2.items():
            if c >= local_ms:
                yield p

    candidates = set(baskets.mapPartitions(local_apriori).distinct().collect())
    bc = spark.sparkContext.broadcast(candidates)
    counts = (baskets.flatMap(lambda b: [p for p in combinations(sorted(b), 2) if p in bc.value])
                     .map(lambda p: (p, 1)).reduceByKey(lambda a, b: a + b)
                     .filter(lambda kv: kv[1] >= ms).collect())
    top = sorted(counts, key=lambda kv: -kv[1])[:15]
    return {"partitions": parts, "baskets": n, "min_support_count": ms, "son_candidates": len(candidates),
            "frequent_pairs": len(counts),
            "top_pairs": [{"items": list(p), "support": round(c / n, 4)} for p, c in top]}


def rdd_pagerank(edges_rdd, beta=0.85, iters=20):
    links = (edges_rdd.flatMap(lambda e: [e, (e[1], e[0])]).distinct().groupByKey()
                      .mapValues(list).partitionBy(8).cache())
    nodes = links.keys()
    n = links.count()
    ranks = nodes.map(lambda v: (v, 1.0 / n))
    for _ in range(iters):
        contribs = links.join(ranks).flatMap(lambda kv: [(w, kv[1][1] / len(kv[1][0])) for w in kv[1][0]])
        ranks = contribs.reduceByKey(lambda a, b: a + b, 8).mapValues(lambda r: (1 - beta) / n + beta * r)
        ranks = ranks.cache()
        ranks.localCheckpoint()              # cut lineage each iteration, otherwise the plan grows every step
        ranks.count()
    top = ranks.filter(lambda kv: kv[0].startswith("net:")).takeOrdered(10, key=lambda kv: -kv[1])
    return {"nodes": n, "iterations": iters, "top_networks": [{"network": k[4:], "rank": round(v * 1000, 3)} for k, v in top]}


def mllib(spark, df):
    feat = F.udf(lambda u: [float(x) for x in extract(u)], T.ArrayType(T.DoubleType()))
    df = df.withColumn("f", feat("url")).select("url", F.col("label").cast("int").alias("label"),
                                                 F.to_timestamp("first_seen").alias("ts"),
                                                 *[F.col("f")[i].alias(n) for i, n in enumerate(FEATURE_NAMES)])
    cutoff = df.agg(F.max("ts")).first()[0]
    cutoff = cutoff.replace(day=cutoff.day) - __import__("datetime").timedelta(days=20)
    data = VectorAssembler(inputCols=FEATURE_NAMES, outputCol="features").transform(df).select("label", "ts", "features").cache()
    train, test = data.where(F.col("ts") <= cutoff), data.where(F.col("ts") > cutoff)
    t0 = time.time()
    model = GBTClassifier(maxIter=30, maxDepth=5, seed=0).fit(train)
    secs = time.time() - t0
    pred = model.transform(test).cache()
    auc = BinaryClassificationEvaluator(metricName="areaUnderROC").evaluate(pred)
    pr = BinaryClassificationEvaluator(metricName="areaUnderPR").evaluate(pred)
    c = pred.groupBy("label", "prediction").count().collect()
    cm = {(r["label"], int(r["prediction"])): r["count"] for r in c}
    tp, fp, fn = cm.get((1, 1), 0), cm.get((0, 1), 0), cm.get((1, 0), 0)
    imp = sorted(zip(FEATURE_NAMES, model.featureImportances.toArray()), key=lambda x: -x[1])[:8]
    return {"train_rows": train.count(), "test_rows": test.count(), "train_seconds": round(secs, 1),
            "roc_auc": round(auc, 4), "pr_auc": round(pr, 4),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "feature_importance": [{"feature": f, "importance": round(float(v), 4)} for f, v in imp]}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?", default=str(config.EVENTS_CSV))
    ap.add_argument("--only", choices=["son", "pagerank", "mllib"], action="append")
    a = ap.parse_args()
    steps = set(a.only or ["son", "pagerank", "mllib"])
    src = a.input
    spark = SparkSession.builder.appName("phishstream-analytics").config("spark.ui.enabled", "false").getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")
    df = spark.read.option("header", True).csv(src).repartition(8)
    ph = df.where("label = '1'").cache()
    path = config.ARTIFACTS / "spark_results.json"
    out = json.loads(path.read_text()) if path.exists() else {}
    t = out.get("timings_s", {})
    if "son" in steps:
        t0 = time.time(); out["son"] = son(spark, ph.rdd.map(lambda r: r["url"]), ph.count()); t["son"] = round(time.time() - t0, 1)
        print("SON:", {k: v for k, v in out["son"].items() if k != "top_pairs"})
    if "pagerank" in steps:
        t0 = time.time()
        edges = ph.where("ip != ''").rdd.flatMap(lambda r: [(f"d:{registered_domain(split(r['url'])[1]) or r['ip']}", f"ip:{r['ip']}")]
                                                  + ([(f"ip:{r['ip']}", f"net:{r['network']}")] if r["network"] else []))
        out["pagerank"] = rdd_pagerank(edges) if not edges.isEmpty() else {"available": False}
        t["pagerank"] = round(time.time() - t0, 1)
        print("PageRank top 3:", out["pagerank"].get("top_networks", [])[:3])
    if "mllib" in steps:
        t0 = time.time(); out["mllib_gbt"] = mllib(spark, df); t["mllib"] = round(time.time() - t0, 1)
        print("MLlib GBT:", {k: v for k, v in out["mllib_gbt"].items() if k != "feature_importance"})
    out["timings_s"] = t
    path.write_text(json.dumps(out, indent=2))
    spark.stop()


if __name__ == "__main__":
    main()
