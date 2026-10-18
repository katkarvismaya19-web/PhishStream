"""
Distributed Bloom filter build with Spark (the MapReduce pattern):
  map    : each partition hashes its URLs and builds a PARTIAL Bloom filter
  reduce : partial filters are merged with bitwise OR (associative + commutative -> treeReduce)
Result is bit-for-bit identical to the single-machine build.

spark-submit spark_jobs/build_bloom_spark.py [input_csv_or_hdfs_path] [replicate_factor]
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pyspark.sql import SparkSession  # noqa: E402

from phishstream import config  # noqa: E402
from phishstream.sketches.bloom import BloomFilter, optimal_params, positions  # noqa: E402
from phishstream.stream.engine import normalize  # noqa: E402


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else str(config.EVENTS_CSV)
    spark = (SparkSession.builder.appName("phishstream-bloom").config("spark.ui.enabled", "false").getOrCreate())
    df = spark.read.option("header", True).option("multiLine", False).csv(src)
    cutoff = df.selectExpr("max(to_timestamp(first_seen)) - INTERVAL 20 DAYS as c").first()["c"]
    keys = (df.where("label = '1'").where(df.first_seen.cast("timestamp") <= cutoff)
              .rdd.map(lambda r: normalize(r["url"])).distinct().repartition(8).cache())
    n = keys.count()
    m, k = optimal_params(n, config.BLOOM_FP)
    t0 = time.time()

    def partial(it):
        bf = BloomFilter(m, k)
        c = 0
        for key in it:
            bf.set_positions(positions(key, m, k)); c += 1
        bf.count = c
        yield bf

    merged = keys.mapPartitions(partial).treeReduce(lambda a, b: a.union(b))
    secs = time.time() - t0
    out = config.ARTIFACTS / "bloom_spark.bin"
    out.write_bytes(merged.to_bytes())
    same = None
    if config.BLOOM_PATH.exists():
        same = BloomFilter.from_bytes(config.BLOOM_PATH.read_bytes()).bits == merged.bits
    print(f"Spark Bloom build: {n:,} URLs over {keys.getNumPartitions()} partitions in {secs:.1f}s, "
          f"m = {m:,}, k = {k}. Identical to single-machine build: {same}")
    spark.stop()


if __name__ == "__main__":
    main()
