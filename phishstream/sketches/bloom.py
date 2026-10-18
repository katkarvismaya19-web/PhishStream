"""Bloom filter with optimal sizing, double hashing, union (for distributed builds) and persistence."""
import hashlib
import math


def optimal_params(n: int, p: float) -> tuple[int, int]:
    m = math.ceil(-(n * math.log(p)) / (math.log(2) ** 2))
    return m, max(1, round((m / n) * math.log(2)))


def positions(item: str, m: int, k: int) -> list[int]:
    """Kirsch-Mitzenmacher double hashing: h_i = h1 + i*h2 (mod m)."""
    d = hashlib.blake2b(item.encode(), digest_size=16).digest()
    h1 = int.from_bytes(d[:8], "big")
    h2 = int.from_bytes(d[8:], "big") | 1
    return [(h1 + i * h2) % m for i in range(k)]


class BloomFilter:
    def __init__(self, m: int, k: int):
        self.m, self.k, self.count = m, k, 0
        self.bits = bytearray((m + 7) // 8)

    @classmethod
    def for_capacity(cls, n: int, p: float = 0.001):
        return cls(*optimal_params(max(n, 1), p))

    def add(self, item: str):
        for p in positions(item, self.m, self.k):
            self.bits[p >> 3] |= 1 << (p & 7)
        self.count += 1

    def set_positions(self, ps):
        for p in ps:
            self.bits[p >> 3] |= 1 << (p & 7)

    def __contains__(self, item: str) -> bool:
        return all(self.bits[p >> 3] & (1 << (p & 7)) for p in positions(item, self.m, self.k))

    def union(self, other: "BloomFilter") -> "BloomFilter":
        """Bitwise OR: lets each Spark partition build a partial filter, then merge."""
        assert (self.m, self.k) == (other.m, other.k)
        out = BloomFilter(self.m, self.k)
        out.bits = bytearray(a | b for a, b in zip(self.bits, other.bits))
        out.count = self.count + other.count
        return out

    def fill_ratio(self) -> float:
        return sum(bin(b).count("1") for b in self.bits) / self.m

    def expected_fp(self) -> float:
        return (1 - math.exp(-self.k * self.count / self.m)) ** self.k

    def nbytes(self) -> int:
        return len(self.bits)

    def to_bytes(self) -> bytes:
        header = f"{self.m},{self.k},{self.count}\n".encode()
        return header + bytes(self.bits)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "BloomFilter":
        header, body = raw.split(b"\n", 1)
        m, k, c = map(int, header.decode().split(","))
        bf = cls(m, k)
        bf.bits, bf.count = bytearray(body), c
        return bf
