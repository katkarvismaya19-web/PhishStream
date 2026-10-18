import random

from phishstream.sketches.bloom import BloomFilter
from phishstream.sketches.countmin import CountMinSketch
from phishstream.sketches.dgim import DGIM
from phishstream.sketches.hyperloglog import HyperLogLog
from phishstream.sketches.minhash import MinHashLSH, jaccard, shingles
from phishstream.sketches.reservoir import Reservoir


def test_bloom_no_false_negatives_and_fp_near_target():
    bf = BloomFilter.for_capacity(20_000, 0.01)
    items = [f"bad{i}.xyz/login" for i in range(20_000)]
    for x in items:
        bf.add(x)
    assert all(x in bf for x in items)
    fp = sum(f"ok{i}.com" in bf for i in range(50_000)) / 50_000
    assert fp < 0.02


def test_bloom_union_equals_single_build():
    a, b, full = BloomFilter(10_000, 5), BloomFilter(10_000, 5), BloomFilter(10_000, 5)
    for i in range(1000):
        (a if i % 2 else b).add(str(i)); full.add(str(i))
    assert a.union(b).bits == full.bits


def test_bloom_roundtrip():
    bf = BloomFilter.for_capacity(100)
    bf.add("x")
    assert "x" in BloomFilter.from_bytes(bf.to_bytes())


def test_dgim_within_50_percent():
    rng, d, bits = random.Random(0), DGIM(1000), []
    for _ in range(20_000):
        b = int(rng.random() < 0.3); d.add(b); bits.append(b)
        exact = sum(bits[-1000:])
        if exact:
            assert abs(d.count() - exact) <= 0.5 * exact + 1


def test_dgim_bucket_rule():
    d = DGIM(10_000)
    for _ in range(5000):
        d.add(1)
    sizes = [s for _, s in d.buckets]
    assert all(sizes.count(s) <= 2 for s in set(sizes))
    assert all(s & (s - 1) == 0 for s in sizes)          # powers of two


def test_hll_error():
    h = HyperLogLog(12)
    for i in range(50_000):
        h.add(f"h{i}")
    assert abs(h.count() - 50_000) / 50_000 < 0.06


def test_hll_merge():
    a, b = HyperLogLog(10), HyperLogLog(10)
    for i in range(5000):
        (a if i % 2 else b).add(str(i))
    a.merge(b)
    assert abs(a.count() - 5000) / 5000 < 0.1


def test_countmin_never_underestimates():
    c = CountMinSketch(0.01, 0.01)
    for i in range(5000):
        c.add(f"k{i % 50}")
    assert all(c.estimate(f"k{i}") >= 100 for i in range(50))


def test_reservoir_size():
    r = Reservoir(10, seed=1)
    for i in range(1000):
        r.add(i)
    assert len(r.items) == 10 and r.n == 1000


def test_lsh_finds_lookalikes():
    lsh = MinHashLSH(64, 16)
    names = ["sbi-kyc-update", "sbi-kyc-updates", "sbikycupdate", "netflix-billing", "random-bakery"]
    for n in names:
        lsh.insert(n, shingles(n))
    pairs = lsh.candidate_pairs()
    assert ("sbi-kyc-update", "sbi-kyc-updates") in pairs
    assert jaccard(shingles("sbi-kyc-update"), shingles("random-bakery")) < 0.2
