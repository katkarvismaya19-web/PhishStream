"""Event simulator: replays the held-out (future) URLs as a live stream, with optional campaign bursts.
Used by the local engine, the Kafka producer and the benchmarks."""
import random

from phishstream.data import load, time_split


class EventSource:
    def __init__(self, seed=None, malicious_ratio=0.04):
        df = load()
        train, test, _ = time_split(df)          # new URLs come from the future window the model never saw
        self.known = train.loc[train.label == 1, "url"].tolist()   # old scam links keep circulating
        self.safe = test.loc[test.label == 0, "url"].tolist()
        self.bad = test.loc[test.label == 1, "url"].tolist()
        self.camps = {}
        if "campaign_id" in test:
            for u, c in zip(test["url"], test["campaign_id"]):
                if c:
                    self.camps.setdefault(c, []).append(u)
        self.big = [v for v in self.camps.values() if len(v) >= 8] or [self.bad]
        self.rng = random.Random(seed)
        self.ratio = malicious_ratio
        self.burst_left, self.burst_pool = 0, []

    def burst(self, n=1500):
        self.burst_left, self.burst_pool = n, self.rng.choice(self.big)

    def next(self):
        if self.burst_left > 0:
            self.burst_left -= 1
            if self.rng.random() < 0.45:
                return self.rng.choice(self.burst_pool), 1
        if self.rng.random() < self.ratio:
            pool = self.known if self.rng.random() < 0.35 else self.bad
            return self.rng.choice(pool), 1
        return self.rng.choice(self.safe), 0

    def batch(self, n):
        ev = [self.next() for _ in range(n)]
        return [u for u, _ in ev], [t for _, t in ev]
