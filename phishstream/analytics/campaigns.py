"""
Campaign discovery with MinHash + LSH: look-alike phishing domains (sbi-kyc-update12.xyz,
sbikycupdate.top ...) are grouped into campaigns without comparing all O(n^2) pairs.
Candidate pairs from LSH are verified with exact Jaccard, then merged with union-find.
On synthetic data we measure against the planted campaign_id (purity, pairwise precision).
"""
import time
from collections import Counter, defaultdict

from phishstream.features.url_features import brand_of, registered_domain, split
from phishstream.sketches.minhash import MinHashLSH, jaccard, shingles

THRESHOLD = 0.6
MAX_GAP_HOURS = 72      # look-alike names seen within 3 days of each other = same campaign


class UnionFind:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def stem(host):
    """Domain label without TLD and digits: the part attackers keep across a campaign."""
    rd = registered_domain(host)
    label = host[: -len(rd)] + rd.split(".")[0] if rd else host
    return "".join(ch for ch in label if not ch.isdigit()).strip(".-")


def run(df, max_hosts=60_000) -> dict:
    ph = df[df.label == 1].copy()
    ph["host"] = ph["url"].map(lambda u: split(u)[1])
    ph = ph[~ph["host"].str.replace(".", "", regex=False).str.isdigit()]
    hosts = ph.drop_duplicates("host").head(max_hosts)
    t0 = time.time()
    lsh = MinHashLSH(num_perm=64, bands=16)
    sh = {}
    for h in hosts["host"]:
        sh[h] = shingles(stem(h))
        lsh.insert(h, sh[h])
    cands = lsh.candidate_pairs()
    seen_at = dict(zip(hosts["host"], hosts["first_seen"]))
    uf, verified = UnionFind(), 0
    for a, b in cands:
        close = abs((seen_at[a] - seen_at[b]).total_seconds()) <= MAX_GAP_HOURS * 3600
        if close and jaccard(sh[a], sh[b]) >= THRESHOLD:
            uf.union(a, b); verified += 1
    lsh_s = time.time() - t0
    clusters = defaultdict(list)
    for h in hosts["host"]:
        clusters[uf.find(h)].append(h)
    multi = [c for c in clusters.values() if len(c) >= 3]
    first = dict(zip(ph["host"], ph["first_seen"]))
    last = ph.groupby("host")["first_seen"].max().to_dict()
    lifetimes, top = [], []
    for c in sorted(multi, key=len, reverse=True):
        t_first = min(first[h] for h in c); t_last = max(last[h] for h in c)
        hours = (t_last - t_first).total_seconds() / 3600
        lifetimes.append(hours)
        if len(top) < 12:
            top.append({"size": len(c), "brand": Counter(brand_of(h) for h in c).most_common(1)[0][0],
                        "examples": c[:4], "first_seen": str(t_first), "hours_active": round(hours, 1)})
    n = len(hosts)
    pairs_all = n * (n - 1) // 2
    res = {"hosts": n, "lsh_bands": lsh.b, "lsh_rows": lsh.r, "jaccard_threshold": THRESHOLD, "max_gap_hours": MAX_GAP_HOURS,
           "all_pairs": pairs_all, "candidate_pairs": len(cands), "verified_pairs": verified,
           "comparisons_saved_pct": round((1 - len(cands) / pairs_all) * 100, 4) if pairs_all else 0,
           "seconds": round(lsh_s, 1), "campaigns_found": len(multi),
           "hosts_in_campaigns_pct": round(sum(map(len, multi)) / n * 100, 1) if n else 0,
           "median_lifetime_hours": round(sorted(lifetimes)[len(lifetimes) // 2], 1) if lifetimes else 0,
           "size_distribution": dict(Counter(min(len(c), 50) // 5 * 5 for c in multi)),
           "top_campaigns": top,
           "s_curve": [{"s": s / 10, "p": round(MinHashLSH.candidate_probability(s / 10, lsh.b, lsh.r), 3)} for s in range(11)]}
    truth = dict(zip(hosts["host"], hosts.get("campaign_id", [""] * n)))
    if any(truth.values()):
        pur = [Counter(truth[h] for h in c).most_common(1)[0][1] / len(c) for c in multi]
        res["synthetic_check"] = {"mean_cluster_purity": round(sum(pur) / len(pur), 3) if pur else None,
                                  "planted_campaigns": len({v for v in truth.values() if v})}
    return res
