"""One command to build everything: data -> Bloom filter -> model -> analytics (-> benchmarks).
  python -m phishstream.pipeline            (synthetic data if data/urls.csv is missing)
  python -m phishstream.pipeline --real     (download real feeds first)
  python -m phishstream.pipeline --bench    (also run benchmarks)"""
import argparse
import sys
import time

from phishstream import config


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true")
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--force-data", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    if a.real:
        sys.argv = [sys.argv[0]]
        from phishstream.ingest import real_feeds
        real_feeds.main()
    elif a.force_data or not config.EVENTS_CSV.exists():
        from phishstream.ingest import synthetic
        synthetic.generate()
    from phishstream import build_bloom
    from phishstream.analytics import insights
    from phishstream.ml import train
    print("\n== Bloom filter =="); build_bloom.main()
    print("\n== Model =="); train.main()
    print("\n== Analytics =="); insights.main()
    if a.bench:
        from benchmarks import benchmark
        print("\n== Benchmarks =="); benchmark.main()
    print(f"\nPipeline finished in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
