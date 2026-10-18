"""
Spark Structured Streaming job.
  source : Kafka topic (cluster mode) or a directory of JSON files (local test mode)
  per micro-batch (foreachBatch):
     executors : Bloom check + ML scoring per partition (model loaded once per executor)
     driver    : ordered update of DGIM / HyperLogLog / Count-Min / reservoir, then publish a snapshot
  sink   : Redis key "phishstream:snapshot" (REDIS_URL set) or data/artifacts/live_snapshot.json

spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.13:<your pyspark version> spark_jobs/streaming_job.py --source kafka
python spark_jobs/streaming_job.py --source files --input data/stream_in --seconds 60
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pyspark.sql import SparkSession, functions as F, types as T  # noqa: E402

from phishstream import config  # noqa: E402

SCHEMA = T.StructType([T.StructField("url", T.StringType()), T.StructField("ts", T.LongType()),
                       T.StructField("truth", T.IntegerType())])
_ENGINE = None          # one engine per executor process (model + Bloom filter loaded once)


def executor_engine():
    global _ENGINE
    if _ENGINE is None:
        from phishstream.stream.engine import Engine
        _ENGINE = Engine.from_artifacts()
    return _ENGINE


def score_partition(rows):
    rows = list(rows)
    if not rows:
        return
    eng = executor_engine()
    urls = [r["url"] for r in rows]
    for r, p in zip(rows, eng.score(urls)):
        c = eng.classify(r["url"], float(p))
        yield (r["ts"], r["url"], c["verdict"], c["score"], c["bloom_false_positive"], r["truth"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["kafka", "files"], default="kafka")
    ap.add_argument("--input", default=str(config.DATA / "stream_in"))
    ap.add_argument("--seconds", type=int, default=0, help="stop after N seconds (0 = forever)")
    a = ap.parse_args()
    spark = SparkSession.builder.appName("phishstream-streaming").config("spark.ui.enabled", "false").getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")

    if a.source == "kafka":
        raw = (spark.readStream.format("kafka").option("kafka.bootstrap.servers", config.KAFKA_BOOTSTRAP)
                    .option("subscribe", config.KAFKA_TOPIC).option("startingOffsets", "latest").load())
        events = raw.select(F.from_json(F.col("value").cast("string"), SCHEMA).alias("e")).select("e.*")
    else:
        events = spark.readStream.schema(SCHEMA).option("maxFilesPerTrigger", 2).json(a.input)

    from phishstream.stream.engine import Engine
    driver = Engine.from_artifacts()          # holds the order-dependent sketches
    redis = None
    if config.REDIS_URL:
        import redis as R
        redis = R.from_url(config.REDIS_URL)
    snap_path = config.ARTIFACTS / "live_snapshot.json"
    stats = {"batches": 0, "events": 0, "score_s": 0.0}

    def handle(batch_df, batch_id):
        t0 = time.time()
        res = sorted(batch_df.rdd.mapPartitions(score_partition).collect(), key=lambda x: x[0])
        stats["score_s"] += time.time() - t0
        for ts, url, verdict, score, bfp, truth in res:
            driver._update({"url": url, "verdict": verdict, "score": score, "bloom_false_positive": bfp}, truth)
        stats["batches"] += 1; stats["events"] += len(res)
        snap = driver.snapshot()
        snap["spark"] = {"batch_id": batch_id, "batch_events": len(res), **stats}
        payload = json.dumps(snap, default=str)
        if redis:
            redis.set("phishstream:snapshot", payload)
        else:
            snap_path.write_text(payload)
        print(f"batch {batch_id}: {len(res):,} events, total {stats['events']:,}, wave={snap['wave']['level']}")

    q = events.writeStream.foreachBatch(handle).trigger(processingTime="1 second").start()
    if a.seconds:
        q.awaitTermination(a.seconds); q.stop()
    else:
        q.awaitTermination()
    spark.stop()


if __name__ == "__main__":
    main()
