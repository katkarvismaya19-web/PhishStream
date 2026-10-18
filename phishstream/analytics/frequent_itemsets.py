"""
Frequent itemsets over phishing URLs: each URL is a basket of tokens (brand, bait words, TLD, path words).
Implements Apriori and PCY (Park-Chen-Yu) for pairs, compares candidate counts / memory, then mines
triples and association rules (support, confidence, lift).
"""
import re
import zlib
from collections import Counter
from itertools import combinations

from phishstream.features.url_features import BRANDS, LURE_WORDS, split

TOK = re.compile(r"[a-z]{3,}")
STOP = {"http", "https", "www", "com", "html", "index", "php", "net", "org", "content", "uploads",
        "includes", "files", "images", "assets", "media", "docs", "old"}


def basket(url: str) -> frozenset:
    _, host, path, *_ = split(url)
    items = set()
    for t in TOK.findall(host + " " + path):
        if t in STOP:
            continue
        b = next((b for b in BRANDS if t.startswith(b) or t.endswith(b)), None)
        if b:
            items.add(f"brand:{b}")
        for w in LURE_WORDS:
            if t == w or t.startswith(w):
                items.add(f"word:{w}")
    if "." in host and not host.replace(".", "").isdigit():
        items.add("tld:." + host.rsplit(".", 1)[-1])
    else:
        items.add("host:ip")
    return frozenset(items)


def apriori_pairs(baskets, min_sup):
    c1 = Counter(i for b in baskets for i in b)
    freq1 = {i for i, c in c1.items() if c >= min_sup}
    candidates = len(freq1) * (len(freq1) - 1) // 2          # all pairs of frequent items must be counted
    c2 = Counter(p for b in baskets for p in combinations(sorted(i for i in b if i in freq1), 2))
    return freq1, {p: c for p, c in c2.items() if c >= min_sup}, candidates, c1


def bucket_of(pair, n_buckets):
    return zlib.crc32("|".join(pair).encode()) % n_buckets      # stable across runs (unlike hash())


def pcy_pairs(baskets, min_sup, n_buckets=4999):
    c1, buckets = Counter(), [0] * n_buckets
    for b in baskets:                                         # pass 1: count items AND hash pairs into buckets
        c1.update(b)
        for p in combinations(sorted(b), 2):
            buckets[bucket_of(p, n_buckets)] += 1
    freq1 = {i for i, c in c1.items() if c >= min_sup}
    bitmap = [c >= min_sup for c in buckets]                  # 1 bit per bucket replaces the counts
    c2, candidates = Counter(), set()
    for b in baskets:                                         # pass 2: count only pairs of frequent items in frequent buckets
        for p in combinations(sorted(i for i in b if i in freq1), 2):
            if bitmap[bucket_of(p, n_buckets)]:
                c2[p] += 1
                candidates.add(p)
    return {p: c for p, c in c2.items() if c >= min_sup}, len(candidates), sum(bitmap)


def run(urls, min_support=0.004) -> dict:
    baskets = [basket(u) for u in urls]
    baskets = [b for b in baskets if b]
    n = len(baskets)
    ms = max(2, int(min_support * n))
    freq1, f2_ap, cand_ap, c1 = apriori_pairs(baskets, ms)
    f2_pcy, cand_pcy, frequent_buckets = pcy_pairs(baskets, ms)
    assert set(f2_ap) == set(f2_pcy), "PCY must find exactly the same frequent pairs"

    # triples via Apriori property: every 2-subset must be frequent
    fp = set(f2_ap)
    c3 = Counter()
    for b in baskets:
        items = sorted(i for i in b if i in freq1)
        for t in combinations(items, 3):
            if all(s in fp for s in combinations(t, 2)):
                c3[t] += 1
    f3 = {t: c for t, c in c3.items() if c >= ms}

    sup = {frozenset([i]): c for i, c in c1.items()}
    sup.update({frozenset(p): c for p, c in f2_ap.items()})
    sup.update({frozenset(t): c for t, c in f3.items()})
    rules = []
    for itemset, c in list(f2_ap.items()) + list(f3.items()):
        for k in range(1, len(itemset)):
            for lhs in combinations(itemset, k):
                rhs = tuple(i for i in itemset if i not in lhs)
                conf = c / sup[frozenset(lhs)]
                lift = conf / (sup[frozenset(rhs)] / n)
                if conf >= 0.5 and lift > 1.2:
                    rules.append({"if": list(lhs), "then": list(rhs), "support": round(c / n, 4),
                                  "confidence": round(conf, 3), "lift": round(lift, 2)})
    rules.sort(key=lambda r: (-r["support"] * r["lift"], -r["confidence"]))
    seen, uniq = set(), []                       # one rule per itemset, so a single big campaign can't fill the list
    for r in rules:
        key = frozenset(r["if"] + r["then"])
        if key not in seen:
            seen.add(key); uniq.append(r)
    rules = uniq
    top = lambda d: [{"items": list(k), "support": round(v / n, 4), "count": v}
                     for k, v in sorted(d.items(), key=lambda x: -x[1])[:15]]
    return {"baskets": n, "min_support_count": ms, "frequent_items": len(freq1),
            "frequent_pairs": top(f2_ap), "frequent_pairs_total": len(f2_ap), "frequent_triples_total": len(f3), "frequent_triples": top(f3), "rules": rules[:20],
            "apriori_candidate_pairs": cand_ap, "pcy_candidate_pairs": cand_pcy,
            "pcy_frequent_buckets": frequent_buckets, "pcy_same_result_as_apriori": True}
