"""
Build data/urls.csv from REAL sources (needs internet):
  phishing : URLhaus recent CSV (abuse.ch, has timestamps), OpenPhish community feed,
             PhishTank (optional, set PHISHTANK_KEY)
  safe     : Tranco top-1M domains (research ranking), with realistic paths added because
             Tranco lists bare domains and phishing URLs have paths (prevents a length shortcut)
Optional --resolve N : DNS-resolve N phishing hosts to IPs so PageRank can analyse infrastructure.

Usage: python -m phishstream.ingest.real_feeds [--safe 150000] [--resolve 20000]
"""
import argparse
import csv
import io
import random
import socket
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from phishstream.config import EVENTS_CSV
from phishstream.ingest.synthetic import SAFE_PATH_TOKENS, rand_word

UA = {"User-Agent": "PhishStream research project"}


def get(url, timeout=120):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def host_of(url):
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def urlhaus():
    raw = get("https://urlhaus.abuse.ch/downloads/csv_recent/").decode("utf-8", "ignore")
    lines = [l for l in raw.splitlines() if l and not l.startswith("#")]
    for row in csv.reader(lines):
        if len(row) >= 3:
            yield row[2], row[1].replace(" ", "T")[:16], "urlhaus"


def openphish():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    for line in get("https://openphish.com/feed.txt").decode().splitlines():
        if line.strip():
            yield line.strip(), now, "openphish"


def phishtank(key):
    raw = get(f"http://data.phishtank.com/data/{key}/online-valid.csv").decode("utf-8", "ignore")
    for row in csv.DictReader(io.StringIO(raw)):
        yield row["url"], row["submission_time"][:16], "phishtank"


def tranco(n):
    z = zipfile.ZipFile(io.BytesIO(get("https://tranco-list.eu/top-1m.csv.zip")))
    rng = random.Random(7)
    with z.open(z.namelist()[0]) as f:
        for i, line in enumerate(io.TextIOWrapper(f)):
            if i >= n:
                break
            dom = line.strip().split(",")[1]
            depth = rng.choices([0, 1, 2, 3], weights=[20, 35, 30, 15])[0]
            path = "/".join(rng.choice(SAFE_PATH_TOKENS) if rng.random() < .6 else rand_word() for _ in range(depth))
            yield f"https://{rng.choice(['', 'www.'])}{dom}/{path}", dom


def resolve(hosts, workers=64):
    socket.setdefaulttimeout(3)

    def one(h):
        try:
            return h, socket.gethostbyname(h)
        except OSError:
            return h, ""
    with ThreadPoolExecutor(workers) as ex:
        return dict(ex.map(one, hosts))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--safe", type=int, default=150_000)
    ap.add_argument("--resolve", type=int, default=0)
    ap.add_argument("--phishtank-key", default="")
    a = ap.parse_args()

    rows, seen = [], set()
    sources = [("URLhaus", urlhaus), ("OpenPhish", openphish)]
    if a.phishtank_key:
        sources.append(("PhishTank", lambda: phishtank(a.phishtank_key)))
    for name, fn in sources:
        try:
            before = len(rows)
            for url, ts, src in fn():
                if url not in seen:
                    seen.add(url)
                    rows.append({"url": url, "label": 1, "first_seen": ts, "source": src, "host": host_of(url)})
            print(f"{name:10s}: {len(rows) - before:,} phishing URLs")
        except Exception as e:
            print(f"{name:10s}: failed ({e})")
    if not rows:
        raise SystemExit("No phishing feed reachable. Use: python -m phishstream.ingest.synthetic")

    if a.resolve:
        hosts = list({r["host"] for r in rows if r["host"]})[:a.resolve]
        print(f"Resolving {len(hosts):,} hosts ...")
        ips = resolve(hosts)
        for r in rows:
            ip = ips.get(r["host"], "")
            r["ip"] = ip
            r["network"] = ".".join(ip.split(".")[:3]) + ".0/24" if ip else ""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    n_safe = 0
    for url, dom in tranco(a.safe):
        if url not in seen:
            seen.add(url); n_safe += 1
            rows.append({"url": url, "label": 0, "first_seen": now, "source": "tranco", "host": dom})
    print(f"Tranco    : {n_safe:,} safe URLs")

    fields = ["url", "label", "first_seen", "source", "host", "ip", "network", "country", "brand", "lure", "campaign_id"]
    with open(EVENTS_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})
    print(f"Wrote {len(rows):,} rows -> {EVENTS_CSV}")


if __name__ == "__main__":
    main()
