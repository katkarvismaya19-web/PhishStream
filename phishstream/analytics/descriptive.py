"""Descriptive analytics: who is targeted, which lures and domain endings, when attacks happen, where hosted."""
from collections import Counter

import pandas as pd

from phishstream.features.url_features import LURE_WORDS, brand_of, split


def tld(host):
    return "." + host.rsplit(".", 1)[-1] if "." in host and not host.replace(".", "").isdigit() else "(ip)"


def run(df: pd.DataFrame) -> dict:
    ph = df[df.label == 1].copy()
    hosts = ph["url"].map(lambda u: split(u)[1])
    ph["brand_d"] = ph["url"].map(brand_of)
    ph["tld"] = hosts.map(tld)
    lure_counts = Counter(w for u in ph["url"].str.lower() for w in LURE_WORDS if w in u)

    hour = ph["first_seen"].dt.hour.value_counts().reindex(range(24), fill_value=0)
    dow = ph["first_seen"].dt.day_name().value_counts()
    dom = ph["first_seen"].dt.day
    weekly = (ph.set_index("first_seen").resample("W")["url"].count())
    top_brands = ph.loc[ph.brand_d != "", "brand_d"].value_counts().head(12)
    brand_weekly = {}
    for b in top_brands.index[:5]:
        s = ph[ph.brand_d == b].set_index("first_seen").resample("W")["url"].count()
        brand_weekly[b] = {str(k.date()): int(v) for k, v in s.items()}

    bill = ph[ph["url"].str.contains("bill|power|electric", case=False)]
    bill_month_end = float((bill["first_seen"].dt.day >= 24).mean()) if len(bill) else 0.0
    https_share = float(ph["url"].str.startswith("https").mean())
    country = ph.loc[ph.get("country", "") != "", "country"].value_counts().head(8) if "country" in ph else pd.Series(dtype=int)

    return {
        "n_phishing": int(len(ph)), "n_safe": int((df.label == 0).sum()),
        "date_range": [str(ph.first_seen.min().date()), str(ph.first_seen.max().date())],
        "top_brands": {k: int(v) for k, v in top_brands.items()},
        "brand_share_pct": round(float((ph.brand_d != "").mean() * 100), 1),
        "top_lures": dict(lure_counts.most_common(12)),
        "top_tlds": {k: int(v) for k, v in ph["tld"].value_counts().head(12).items()},
        "by_hour": [int(x) for x in hour.tolist()],
        "by_weekday": {k: int(v) for k, v in dow.items()},
        "weekly_volume": {str(k.date()): int(v) for k, v in weekly.items()},
        "brand_weekly": brand_weekly,
        "bill_scams_month_end_pct": round(bill_month_end * 100, 1),
        "day_of_month_bill": [int((bill["first_seen"].dt.day == d).sum()) for d in range(1, 32)],
        "https_share_pct": round(https_share * 100, 1),
        "top_countries": {k: int(v) for k, v in country.items()},
        "peak_hour": int(hour.idxmax()),
    }
