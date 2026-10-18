"""Shingling + MinHash + LSH banding to find near-duplicate (look-alike) domains.
P(two items become candidates) = 1 - (1 - s^r)^b  for Jaccard similarity s, b bands of r rows."""
import hashlib
from collections import defaultdict

import numpy as np

PRIME = (1 << 31) - 1


def shingles(text: str, k: int = 3) -> set[str]:
    text = f"^{text}$"
    return {text[i:i + k] for i in range(max(1, len(text) - k + 1))}


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def _h(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=4).digest(), "big") % PRIME


class MinHashLSH:
    def __init__(self, num_perm: int = 64, bands: int = 16, seed: int = 1):
        assert num_perm % bands == 0
        self.n, self.b, self.r = num_perm, bands, num_perm // bands
        rng = np.random.default_rng(seed)
        self.a = rng.integers(1, PRIME, num_perm, dtype=np.int64)
        self.c = rng.integers(0, PRIME, num_perm, dtype=np.int64)
        self.tables = [defaultdict(list) for _ in range(bands)]
        self.sigs: dict = {}

    def signature(self, sh: set[str]) -> np.ndarray:
        h = np.fromiter((_h(s) for s in sh), dtype=np.int64, count=len(sh))
        return ((np.outer(h, self.a) + self.c) % PRIME).min(axis=0)       # min over shingles per permutation

    def insert(self, key, sh: set[str]):
        sig = self.signature(sh)
        self.sigs[key] = sig
        for i in range(self.b):
            self.tables[i][sig[i * self.r:(i + 1) * self.r].tobytes()].append(key)

    def candidate_pairs(self, max_bucket: int = 300):
        pairs = set()
        for table in self.tables:
            for bucket in table.values():
                if 1 < len(bucket) <= max_bucket:
                    bucket = sorted(bucket)
                    for i in range(len(bucket)):
                        for j in range(i + 1, len(bucket)):
                            pairs.add((bucket[i], bucket[j]))
        return pairs

    def est_similarity(self, a, b) -> float:
        return float((self.sigs[a] == self.sigs[b]).mean())

    @staticmethod
    def candidate_probability(s: float, b: int, r: int) -> float:
        return 1 - (1 - s ** r) ** b
