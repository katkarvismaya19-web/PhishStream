"""K-means on URL feature vectors of phishing URLs to discover scam 'families' (k chosen by silhouette)."""
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

from phishstream.features.url_features import FEATURE_NAMES, extract

DESCRIBE = {"is_ip_host": "raw IP host", "free_host": "free hosting", "has_wp_path": "inside hacked WordPress folders",
            "risky_tld": "cheap risky TLD", "brand_in_host_unofficial": "brand name in domain",
            "shortener": "link shortener", "n_digits_host": "digits in domain", "has_port": "custom port",
            "n_hyphens_host": "hyphenated domain", "n_lure_words": "bait words", "path_depth": "deep paths",
            "official_domain": "official domain"}


def run(urls, sample=12_000, seed=0) -> dict:
    rng = np.random.default_rng(seed)
    urls = list(urls)
    if len(urls) > sample:
        urls = [urls[i] for i in rng.choice(len(urls), sample, replace=False)]
    X = np.array([extract(u) for u in urls], dtype=float)
    Xs = StandardScaler().fit_transform(X)
    best, scores = None, {}
    for k in range(3, 9):
        km = KMeans(n_clusters=k, n_init=5, random_state=seed).fit(Xs)
        scores[k] = float(silhouette_score(Xs, km.labels_, sample_size=4000, random_state=seed))
        if best is None or scores[k] > scores[best[0]]:
            best = (k, km)
    k, km = best
    overall = X.mean(axis=0)
    families = []
    for c in range(k):
        m = km.labels_ == c
        mean = X[m].mean(axis=0)
        lift = {f: (mean[i] + 1e-6) / (overall[i] + 1e-6) for i, f in enumerate(FEATURE_NAMES) if f in DESCRIBE}
        traits = [DESCRIBE[f] for f, v in sorted(lift.items(), key=lambda x: -x[1]) if v > 1.5][:3]
        families.append({"cluster": c, "share_pct": round(m.mean() * 100, 1),
                         "traits": traits or ["mixed"], "example": urls[int(np.where(m)[0][0])]})
    families.sort(key=lambda f: -f["share_pct"])
    return {"k": k, "silhouette_by_k": {str(a): round(b, 3) for a, b in scores.items()}, "families": families}
