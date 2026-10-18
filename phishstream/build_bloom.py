"""Builds the Bloom filter + exact blacklist store from the TRAINING-period phishing URLs
(the filter knows the past; the model has to handle the future). Single-machine version;
spark_jobs/build_bloom_spark.py does the same in parallel and produces an identical filter."""
from phishstream import config
from phishstream.data import load, time_split
from phishstream.sketches.bloom import BloomFilter
from phishstream.stream.engine import normalize


def main():
    train, _, _ = time_split(load())
    keys = sorted({normalize(u) for u in train.loc[train.label == 1, "url"]})
    bf = BloomFilter.for_capacity(len(keys), config.BLOOM_FP)
    for k in keys:
        bf.add(k)
    config.BLOOM_PATH.write_bytes(bf.to_bytes())
    (config.ARTIFACTS / "blacklist.txt").write_text("\n".join(keys))
    print(f"Bloom filter: {len(keys):,} URLs, m = {bf.m:,} bits ({bf.nbytes() / 1024:.1f} KB), k = {bf.k}, "
          f"expected FP {bf.expected_fp() * 100:.3f}%")


if __name__ == "__main__":
    main()
