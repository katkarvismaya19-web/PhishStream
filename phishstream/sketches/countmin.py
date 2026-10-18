"""Count-Min Sketch with a heavy-hitter heap: approximate per-key frequencies in fixed memory.
Error <= eps * N with probability 1 - delta, width = e/eps, depth = ln(1/delta)."""
import hashlib
import heapq
import math


class CountMinSketch:
    def __init__(self, eps: float = 0.001, delta: float = 0.01, top_k: int = 15):
        self.w = math.ceil(math.e / eps)
        self.d = math.ceil(math.log(1 / delta))
        self.table = [[0] * self.w for _ in range(self.d)]
        self.total, self.top_k, self.heavy = 0, top_k, {}

    def _cols(self, key):
        h = hashlib.blake2b(key.encode(), digest_size=16).digest()
        a, b = int.from_bytes(h[:8], "big"), int.from_bytes(h[8:], "big") | 1
        return [(a + i * b) % self.w for i in range(self.d)]

    def add(self, key: str, c: int = 1):
        self.total += c
        cols = self._cols(key)
        for row, col in enumerate(cols):
            self.table[row][col] += c
        est = min(self.table[r][col] for r, col in enumerate(cols))
        self.heavy[key] = est
        if len(self.heavy) > self.top_k * 4:                 # keep candidate set small
            self.heavy = dict(heapq.nlargest(self.top_k * 2, self.heavy.items(), key=lambda x: x[1]))

    def estimate(self, key: str) -> int:
        return min(self.table[r][c] for r, c in enumerate(self._cols(key)))

    def top(self, k=None):
        k = k or self.top_k
        return heapq.nlargest(k, ((key, self.estimate(key)) for key in self.heavy), key=lambda x: x[1])

    def nbytes(self):
        return self.w * self.d * 4
