"""Runs every analytics module over the dataset and writes data/artifacts/insights.json,
including plain-language findings generated from the numbers.
Usage: python -m phishstream.analytics.insights"""
import json
import time

from phishstream.analytics import campaigns, clustering, descriptive, frequent_itemsets, pagerank
from phishstream.config import INSIGHTS_PATH
from phishstream.data import load


def findings(d, fi, pr, cp, cl):
    out = []
    tb = list(d["top_brands"].items())
    if tb:
        top3 = sum(v for _, v in tb[:3]) / d["n_phishing"] * 100
        out.append(f"{d['brand_share_pct']}% of phishing URLs impersonate a known brand; the top three "
                   f"({', '.join(b for b, _ in tb[:3])}) alone account for {top3:.1f}%.")
    out.append(f"Phishing activity peaks around {d['peak_hour']}:00, and {d['https_share_pct']}% of phishing links "
               f"use HTTPS, so the padlock is not a sign of safety.")
    if d["bill_scams_month_end_pct"]:
        out.append(f"{d['bill_scams_month_end_pct']}% of electricity-bill scams appear from the 24th of the month "
                   f"onwards, when real bills are due.")
    tt = list(d["top_tlds"].items())[:3]
    out.append("Most used domain endings: " + ", ".join(f"{k} ({v:,})" for k, v in tt) + ".")
    if fi["rules"]:
        r = fi["rules"][0]
        out.append(f"Strongest lure pattern: URLs with {' + '.join(r['if'])} also contain {' + '.join(r['then'])} "
                   f"{r['confidence'] * 100:.0f}% of the time (lift {r['lift']}).")
    out.append(f"PCY counted {fi['pcy_candidate_pairs']:,} candidate pairs versus Apriori's {fi['apriori_candidate_pairs']:,}, "
               f"finding the identical frequent pairs.")
    if pr.get("available"):
        t = pr["top_networks"][0]
        out.append(f"PageRank ranks network {t['network']} highest: it hosts {t['domains']:,} distinct phishing domains.")
        if "synthetic_check" in pr:
            s = pr["synthetic_check"]
            out.append(f"PageRank recovered {s['found_in_top8']} of the {s['planted_bulletproof_networks']} planted bulletproof networks in its top 8.")
    out.append(f"LSH grouped {cp['hosts_in_campaigns_pct']}% of phishing hosts into {cp['campaigns_found']:,} campaigns while "
               f"skipping {cp['comparisons_saved_pct']}% of pairwise comparisons; the median campaign stayed active "
               f"{cp['median_lifetime_hours']} hours.")
    if "synthetic_check" in cp and cp["synthetic_check"]["mean_cluster_purity"]:
        out.append(f"Campaign clusters are {cp['synthetic_check']['mean_cluster_purity'] * 100:.0f}% pure against the planted campaign labels.")
    fam = ", ".join(f"{f['share_pct']}% {' / '.join(f['traits'][:2])}" for f in cl["families"][:3])
    out.append(f"K-means (k = {cl['k']}) splits phishing into families: {fam}.")
    return out


def main():
    df = load()
    timings, res = {}, {}
    for name, fn in [("descriptive", lambda: descriptive.run(df)),
                     ("frequent_itemsets", lambda: frequent_itemsets.run(df.loc[df.label == 1, "url"])),
                     ("pagerank", lambda: pagerank.run(df)),
                     ("campaigns", lambda: campaigns.run(df)),
                     ("clustering", lambda: clustering.run(df.loc[df.label == 1, "url"]))]:
        t0 = time.time()
        res[name] = fn()
        timings[name] = round(time.time() - t0, 1)
        print(f"{name:18s} done in {timings[name]}s")
    res["findings"] = findings(res["descriptive"], res["frequent_itemsets"], res["pagerank"],
                               res["campaigns"], res["clustering"])
    res["timings_s"] = timings
    res["data_source"] = sorted(df["source"].unique().tolist())
    INSIGHTS_PATH.write_text(json.dumps(res, indent=2, default=str))
    print("\n".join("- " + f for f in res["findings"]))


if __name__ == "__main__":
    main()
