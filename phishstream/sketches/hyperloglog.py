"""HyperLogLog: distinct-count estimation (successor of Flajolet-Martin). Std error ~ 1.04/sqrt(2^p)."""
import hashlib
import math


class HyperLogLog:
    def __init__(self, p: int = 12):
        self.p, self.m = p, 1 << p
        self.reg = bytearray(self.m)
        self.alpha = 0.7213 / (1 + 1.079 / self.m)

    def add(self, item: str):
        x = int.from_bytes(hashlib.blake2b(item.encode(), digest_size=8).digest(), "big")
        j = x >> (64 - self.p)
        w = x & ((1 << (64 - self.p)) - 1)
        rank = (64 - self.p) - w.bit_length() + 1      # position of leftmost 1 = trailing-zero idea of FM
        if rank > self.reg[j]:
            self.reg[j] = rank

    def count(self) -> int:
        z = sum(2.0 ** -r for r in self.reg)
        est = self.alpha * self.m * self.m / z
        zeros = self.reg.count(0)
        if est <= 2.5 * self.m and zeros:              # small-range correction (linear counting)
            est = self.m * math.log(self.m / zeros)
        return int(est)

    def merge(self, other: "HyperLogLog"):
        self.reg = bytearray(max(a, b) for a, b in zip(self.reg, other.reg))

    def nbytes(self):
        return self.m
