"""
PageRank on the phishing infrastructure graph.
Nodes: registered domains, IP addresses and /24 networks.  Edges (both directions):
domain <-> IP it resolved to, IP <-> its network.  A network that many scam domains point to collects
rank, so the top-ranked networks are the shared hosting behind many campaigns.
Power iteration with taxation (teleport, beta = 0.85); dead ends redistribute rank uniformly.
"""
from collections import defaultdict

from phishstream.features.url_features import registered_domain, split


def pagerank(edges, beta=0.85, iters=50, tol=1e-9):
    out = defaultdict(set)
    nodes = set()
    for a, b in edges:
        out[a].add(b); out[b].add(a); nodes |= {a, b}
    nodes = sorted(nodes)
    n = len(nodes)
    r = {v: 1 / n for v in nodes}
    for it in range(iters):
        nxt = dict.fromkeys(nodes, (1 - beta) / n)
        dangling = sum(r[v] for v in nodes if not out[v])
        for v in nodes:
            if out[v]:
                share = beta * r[v] / len(out[v])
                for w in out[v]:
                    nxt[w] += share
        if dangling:
            for v in nodes:
                nxt[v] += beta * dangling / n
        delta = sum(abs(nxt[v] - r[v]) for v in nodes)
        r = nxt
        if delta < tol:
            break
    return r, it + 1, n


def run(df) -> dict:
    ph = df[(df.label == 1) & (df["ip"] != "")]
    if ph.empty:
        return {"available": False, "reason": "no IP data (run real_feeds with --resolve)"}
    edges = set()
    for url, ip, net in zip(ph["url"], ph["ip"], ph["network"]):
        dom = registered_domain(split(url)[1]) or ip
        edges.add((f"d:{dom}", f"ip:{ip}"))
        if net:
            edges.add((f"ip:{ip}", f"net:{net}"))
    rank, iters, n = pagerank(edges)
    nets = sorted(((k[4:], v) for k, v in rank.items() if k.startswith("net:")), key=lambda x: -x[1])
    ips = sorted(((k[3:], v) for k, v in rank.items() if k.startswith("ip:")), key=lambda x: -x[1])
    net_domains = defaultdict(set)
    for url, net in zip(ph["url"], ph["network"]):
        net_domains[net].add(registered_domain(split(url)[1]))
    res = {"available": True, "nodes": n, "edges": len(edges), "iterations": iters,
           "top_networks": [{"network": k, "rank": round(v * 1000, 3), "domains": len(net_domains[k])} for k, v in nets[:10]],
           "top_ips": [{"ip": k, "rank": round(v * 1000, 3)} for k, v in ips[:10]]}
    if "bulletproof" in df.columns or df["source"].eq("synthetic").any():   # ground truth check on synthetic data
        from phishstream.ingest.synthetic import NETWORKS
        truth = {x["net"] for x in NETWORKS if x["bulletproof"]}
        top8 = {k for k, _ in nets[:8]}
        res["synthetic_check"] = {"planted_bulletproof_networks": len(truth),
                                  "found_in_top8": len(truth & top8),
                                  "precision_at_8": round(len(truth & top8) / 8, 3)}
    return res
