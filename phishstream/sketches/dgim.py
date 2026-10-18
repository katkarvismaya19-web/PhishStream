"""DGIM: estimate the count of 1s in the last N bits in O(log^2 N) space. r buckets per size; r = 2 gives error <= 50%."""


class DGIM:
    def __init__(self, window: int, r: int = 2):
        self.N, self.r, self.t = window, r, 0
        self.buckets: list[list[int]] = []   # [end_timestamp, size], newest first

    def add(self, bit: int):
        self.t += 1
        while self.buckets and self.buckets[-1][0] <= self.t - self.N:
            self.buckets.pop()
        if not bit:
            return
        self.buckets.insert(0, [self.t, 1])
        size = 1
        while True:
            idx = [i for i, b in enumerate(self.buckets) if b[1] == size]
            if len(idx) <= self.r:
                break
            self.buckets[idx[-2]][1] = size * 2
            del self.buckets[idx[-1]]
            size *= 2

    def count(self, k: int | None = None) -> int:
        k = self.N if k is None else min(k, self.N)
        total = last = 0
        for ts, s in self.buckets:
            if ts <= self.t - k:
                break
            total, last = total + s, s
        return total - last // 2

    def snapshot(self):
        return [{"size": s, "age": self.t - ts} for ts, s in self.buckets]
