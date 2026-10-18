"""Publishes simulated URL events to Kafka (or to files for the Spark file source).
  python -m phishstream.stream.producer --sink kafka --rate 5000
  python -m phishstream.stream.producer --sink files --out data/stream_in --batches 20
Each event: {"url": ..., "ts": epoch_ms, "truth": 0/1}. --burst-every N starts a campaign burst."""
import argparse
import json
import time
from pathlib import Path

from phishstream import config
from phishstream.stream.simulator import EventSource


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sink", choices=["kafka", "files"], default="kafka")
    ap.add_argument("--rate", type=int, default=2000, help="events per second")
    ap.add_argument("--batch", type=int, default=1000)
    ap.add_argument("--batches", type=int, default=0, help="0 = run forever")
    ap.add_argument("--burst-every", type=int, default=30, help="start a campaign burst every N batches")
    ap.add_argument("--out", default=str(config.DATA / "stream_in"))
    a = ap.parse_args()
    src = EventSource()
    producer = None
    if a.sink == "kafka":
        from kafka import KafkaProducer
        producer = KafkaProducer(bootstrap_servers=config.KAFKA_BOOTSTRAP, linger_ms=20,
                                 value_serializer=lambda v: json.dumps(v).encode())
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    i = 0
    while not a.batches or i < a.batches:
        t0 = time.time()
        if a.burst_every and i % a.burst_every == a.burst_every // 2:
            src.burst(a.batch * 3)
        urls, truth = src.batch(a.batch)
        now = int(time.time() * 1000)
        events = [{"url": u, "ts": now, "truth": t} for u, t in zip(urls, truth)]
        if producer:
            for e in events:
                producer.send(config.KAFKA_TOPIC, e)
            producer.flush()
        else:
            (out / f"batch_{i:06d}.json").write_text("\n".join(json.dumps(e) for e in events))
        i += 1
        time.sleep(max(0.0, a.batch / a.rate - (time.time() - t0)))
        if i % 10 == 0:
            print(f"sent {i * a.batch:,} events")


if __name__ == "__main__":
    main()
