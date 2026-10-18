"""
Synthetic dataset generator with realistic structure, used when real feeds are unavailable.

It plants patterns on purpose so every analytics module has something to find, and stores the
ground truth (campaign_id, network) so we can MEASURE whether LSH / PageRank recover it:
  - campaigns: a brand + lure template spawning many look-alike domains over a lifetime
  - infrastructure: a few "bulletproof" networks host many campaigns
  - time: evening peaks, electricity-bill scams at month end, parcel scams near Diwali
  - hard cases: phishing on free hosting / compromised sites; safe URLs with login pages,
    hyphens, long queries; URL shorteners in both classes
Insights computed on this data validate the METHOD. Run ingest/real_feeds.py for real findings.
"""
import csv
import math
import random
from datetime import datetime, timedelta

from phishstream.config import EVENTS_CSV

R = random.Random(2026)
END = datetime(2026, 10, 15)
DAYS = 90
START = END - timedelta(days=DAYS)

BRANDS = {  # weight ~ how often targeted
    "sbi": 14, "hdfc": 9, "icici": 7, "axis": 5, "kotak": 4, "paytm": 8, "phonepe": 7, "gpay": 4,
    "irctc": 5, "amazon": 7, "flipkart": 6, "jio": 4, "airtel": 4, "uidai": 3, "aadhaar": 4,
    "epfo": 3, "incometax": 3, "fastag": 3, "indiapost": 5, "bluedart": 3, "mahavitaran": 4,
    "bescom": 2, "paypal": 5, "microsoft": 6, "netflix": 4, "whatsapp": 4, "instagram": 3, "apple": 3,
}
LURES = {
    "kyc": ["kyc-update", "kyc-verify", "ekyc", "rekyc"], "reward": ["reward", "rewards-points", "redeem"],
    "refund": ["refund", "tax-refund", "itr-refund"], "bill": ["electricity-bill", "bill-pay", "power-cut"],
    "parcel": ["parcel", "track-parcel", "delivery-failed", "redelivery"], "blocked": ["blocked", "suspended", "locked"],
    "login": ["login", "signin", "secure-login", "netbanking"], "prize": ["lucky-draw", "winner", "gift"],
    "job": ["job-offer", "work-from-home", "part-time"], "loan": ["instant-loan", "loan-approved"],
}
RISKY_TLDS = ["xyz", "top", "online", "click", "shop", "site", "live", "icu", "buzz", "vip", "info", "cfd", "sbs", "rest"]
OK_TLDS = ["com", "in", "co.in", "net", "org"]
FREE_HOSTS = ["web.app", "firebaseapp.com", "weebly.com", "github.io", "netlify.app", "vercel.app",
              "ngrok-free.app", "000webhostapp.com", "blogspot.com", "glitch.me"]
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy"]
PATHS = ["login", "verify", "update", "kyc", "account", "secure", "pay", "otp", "confirm", "index.php",
         "auth", "validate", "claim", "redeem", "track", "form", "wp-login.php"]

SAFE_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.in", "amazon.com", "flipkart.com", "onlinesbi.sbi",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "phonepe.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in", "jio.com", "airtel.in",
    "indiapost.gov.in", "bluedart.com", "mahadiscom.in", "paypal.com", "microsoft.com", "live.com",
    "office.com", "netflix.com", "whatsapp.com", "instagram.com", "apple.com", "icloud.com", "github.com",
    "stackoverflow.com", "linkedin.com", "facebook.com", "x.com", "reddit.com", "zomato.com", "swiggy.com",
    "myntra.com", "nykaa.com", "makemytrip.com", "bookmyshow.com", "hotstar.com", "spotify.com",
    "timesofindia.indiatimes.com", "ndtv.com", "thehindu.com", "moneycontrol.com", "zerodha.com", "groww.in",
    "naukri.com", "mu.ac.in", "nptel.ac.in", "geeksforgeeks.org", "w3schools.com", "kaggle.com",
    "coursera.org", "udemy.com", "medium.com", "notion.so", "canva.com", "zoom.us", "slack.com",
    "dropbox.com", "drive.google.com", "docs.google.com", "mail.google.com", "accounts.google.com",
    "login.microsoftonline.com", "outlook.live.com", "economictimes.indiatimes.com", "hindustantimes.com",
    "cricbuzz.com", "espncricinfo.com", "olx.in", "99acres.com", "magicbricks.com", "policybazaar.com",
    "bankbazaar.com", "cred.club", "mobikwik.com", "bharatpe.com", "upstox.com", "angelone.in",
    "licindia.in", "pmkisan.gov.in", "digilocker.gov.in", "umang.gov.in", "cowin.gov.in", "mygov.in",
    "rbi.org.in", "npci.org.in", "github.io", "netlify.app", "vercel.app", "web.app", "blogspot.com",
]
SAFE_SUBS = ["", "", "", "www.", "m.", "help.", "support.", "blog.", "shop.", "secure.", "my."]
SAFE_PATH_TOKENS = ["home", "products", "p", "dp", "search", "account", "login", "signin", "orders", "help",
                    "article", "news", "2026", "10", "category", "user", "settings", "cart", "checkout",
                    "offers", "track", "status", "docs", "en-in", "watch", "blog", "post", "about"]


def wchoice(d):
    keys = list(d)
    return R.choices(keys, weights=[d[k] for k in keys])[0]


def rand_word(n=None):
    n = n or R.randint(4, 9)
    return "".join(R.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


def business_domain():
    words = ["shree", "sai", "ganesh", "krishna", "royal", "star", "metro", "green", "city", "global",
             "tech", "infra", "traders", "foods", "dental", "clinic", "school", "academy", "hotel", "tours"]
    return f"{R.choice(words)}{R.choice(words)}{R.choice(['', str(R.randint(1, 99))])}.{R.choice(OK_TLDS)}"


# ---------------- infrastructure ----------------
COUNTRIES = ["US", "NL", "RU", "SG", "IN", "DE", "HK", "CN", "UA", "FR"]
NETWORKS = []
for i in range(180):
    a, b, c = R.randint(23, 223), R.randint(0, 255), R.randint(0, 255)
    NETWORKS.append({"net": f"{a}.{b}.{c}.0/24", "prefix": f"{a}.{b}.{c}", "country": R.choice(COUNTRIES),
                     "bulletproof": i < 8})


def pick_network():
    if R.random() < 0.45:                                   # bulletproof hosts carry a big share
        return R.choice(NETWORKS[:8])
    return R.choice(NETWORKS[8:])


# ---------------- time patterns ----------------
def hour_sample():
    weights = [1, 1, 1, 1, 1, 2, 3, 4, 5, 7, 9, 10, 10, 9, 8, 7, 7, 8, 10, 12, 13, 11, 7, 3]   # IST
    return R.choices(range(24), weights=weights)[0]


def campaign_start(lure):
    while True:
        d = START + timedelta(days=R.random() * DAYS)
        if lure == "bill" and d.day < 24 and R.random() < 0.7:          # month-end electricity scams
            continue
        if lure == "parcel" and d < END - timedelta(days=25) and R.random() < 0.6:  # festive season ramp
            continue
        return d.replace(hour=hour_sample(), minute=R.randint(0, 59))


# ---------------- phishing URLs ----------------
def phish_campaign(cid):
    brand, lure = wchoice(BRANDS), R.choice(list(LURES))
    style = R.choices(["combo", "typosquat", "freehost", "compromised", "ip"], weights=[42, 13, 15, 25, 5])[0]
    start = campaign_start(lure)
    life_h = max(2, R.lognormvariate(math.log(30), 0.9))           # median ~30 h
    n = max(3, int(R.paretovariate(1.6) * 6))
    nets = [pick_network() for _ in range(R.randint(1, 2))]
    tld = R.choice(RISKY_TLDS)
    stem = f"{brand}-{R.choice(LURES[lure])}" if R.random() < 0.6 else f"{R.choice(LURES[lure])}-{brand}"
    rows = []
    for _ in range(n):
        t = start + timedelta(hours=R.random() * life_h)
        net = R.choice(nets)
        ip = f"{net['prefix']}.{R.randint(2, 254)}"
        if style == "typosquat":                     # clean-looking, no digits, normal TLD
            host = f"{brand}{R.choice(['-', ''])}{R.choice(['netbanking', 'yono', 'care', 'support', 'services', 'portal', 'india', 'customer', 'app'])}.{R.choice(OK_TLDS)}"
            url = f"https://{host}/{R.choice(PATHS + ['', 'home', 'index.html'])}"
        elif style == "combo":
            v = R.random()
            if v < 0.25:
                host = f"{stem}{R.randint(1, 999)}.{tld}"
            elif v < 0.45:
                host = f"{stem}.{tld}"
            elif v < 0.7:
                host = f"{stem.replace('-', '')}{R.choice(['', 'online', 'care', 'india', 'help'])}{R.randint(1, 99)}.{R.choice([tld, R.choice(RISKY_TLDS)])}"
            else:
                host = f"{brand}.{stem}-{R.randint(10, 99)}.{tld}"
            url = f"http{'s' if R.random() < 0.8 else ''}://{host}/{R.choice(PATHS)}"
        elif style == "freehost":
            host = f"{stem}{R.randint(1, 99)}.{R.choice(FREE_HOSTS)}"
            url = f"https://{host}/{R.choice(PATHS)}"
        elif style == "compromised":
            host = business_domain()
            folder = R.choice(["wp-content/uploads", "wp-includes", "images", "files", "docs", "assets/img", "media", "old"])
            sub = R.choice([brand, f"{brand}-{R.choice(LURES[lure])}", rand_word(), "secure", "verify"])
            url = f"http{'s' if R.random() < 0.7 else ''}://{host}/{folder}/{sub}/{R.choice(PATHS)}"
        else:
            host = ip
            url = f"http://{ip}:{R.choice([80, 8080, 8443, 3000])}/{brand}/{R.choice(PATHS)}"
        if R.random() < 0.15:
            url += f"?id={rand_word(12)}&session={R.randint(10**6, 10**9)}"
        rows.append({"url": url, "label": 1, "first_seen": t.isoformat(timespec="minutes"), "source": "synthetic",
                     "host": host, "ip": ip, "network": net["net"], "country": net["country"],
                     "brand": brand, "lure": lure, "campaign_id": cid})
    return rows


NEWS = ["ndtv.com", "timesofindia.indiatimes.com", "moneycontrol.com", "economictimes.indiatimes.com",
        "hindustantimes.com", "livemint.com", "medium.com", "quora.com", "reddit.com", "bankbazaar.com"]
SHOP_WORDS = ["bakery", "house", "mumbai", "eats", "studio", "craft", "decor", "kids", "organic", "tea", "spice", "pet"]


def safe_url():
    v = R.random()
    if v < 0.10:                                                # news / blogs ABOUT scams and brands (hard negatives)
        host = R.choice(NEWS)
        b, l = wchoice(BRANDS), R.choice(list(LURES))
        slug = f"{b}-{R.choice(LURES[l])}-{R.choice(['deadline', 'alert', 'how-to', 'explained', 'new-rules', 'fraud-warning', 'guide'])}-{R.randint(10**6, 10**8)}"
        return f"https://{R.choice(['', 'www.'])}{host}/{R.choice(['business', 'news', 'india', 'tech', 'money'])}/{slug}", host
    if v < 0.17:                                                # real small shops on "risky" TLDs
        host = f"{R.choice(SHOP_WORDS)}{R.choice(SHOP_WORDS)}{R.choice(['', '', str(R.randint(1, 99))])}.{R.choice(['shop', 'store', 'online', 'site', 'xyz', 'live', 'info'])}"
        return f"https://{host}/{R.choice(SAFE_PATH_TOKENS)}", host
    if v < 0.22:                                                # numbered infra hosts
        d = R.choice(SAFE_DOMAINS)
        host = f"{R.choice(['cdn', 'img', 'static', 'm', 'api', 'pay', 'secure', 'ns', 'app'])}{R.randint(1, 40)}.{d}"
        return f"https://{host}/{R.choice(SAFE_PATH_TOKENS)}/{rand_word()}", host
    v = R.random() * 0.78 + 0.0
    if v < 0.04:
        host = R.choice(SHORTENERS)
        return f"https://{host}/{rand_word(7)}", host
    if v < 0.10:                                                # legit sites on free hosting
        host = f"{rand_word()}-{rand_word(5)}.{R.choice(FREE_HOSTS)}"
        return f"https://{host}/{R.choice(SAFE_PATH_TOKENS)}", host
    if v < 0.18:                                                # small businesses (same shape as compromised hosts)
        host = business_domain()
        return f"http{'s' if R.random() < 0.7 else ''}://{host}/{R.choice(SAFE_PATH_TOKENS)}", host
    d = R.choice(SAFE_DOMAINS)
    host = (R.choice(SAFE_SUBS) if d.count(".") == 1 else "") + d
    depth = R.choices([0, 1, 2, 3, 4], weights=[10, 30, 30, 20, 10])[0]
    parts = [R.choice(SAFE_PATH_TOKENS) if R.random() < 0.6 else rand_word() for _ in range(depth)]
    if depth and R.random() < 0.3:
        parts[-1] = f"{rand_word()}-{rand_word()}-{R.randint(100, 99999)}"
    url = f"https://{host}/" + "/".join(parts)
    if R.random() < 0.25:
        url += f"?q={rand_word()}&ref={rand_word(4)}&utm_source={R.choice(['whatsapp', 'sms', 'email'])}"
    return url, host


def generate(n_phish_target=50_000, n_safe=100_000, path=EVENTS_CSV):
    rows, cid = [], 0
    while len(rows) < n_phish_target:
        rows.extend(phish_campaign(f"c{cid:05d}"))
        cid += 1
    rows = rows[:n_phish_target]
    for shortener_noise in range(int(n_phish_target * 0.01)):          # phishing hidden behind shorteners
        r = rows[R.randrange(len(rows))]
        host = R.choice(SHORTENERS)
        rows.append({**r, "url": f"https://{host}/{rand_word(7)}", "host": host})
    for _ in range(n_safe):
        url, host = safe_url()
        t = START + timedelta(days=R.random() * DAYS, hours=0)
        rows.append({"url": url, "label": 0, "first_seen": t.replace(hour=hour_sample()).isoformat(timespec="minutes"),
                     "source": "synthetic", "host": host, "ip": "", "network": "", "country": "",
                     "brand": "", "lure": "", "campaign_id": ""})
    for r in R.sample(rows, int(len(rows) * 0.005)):          # 0.5% label noise, like real feeds
        r["label"] = 1 - r["label"]
    R.shuffle(rows)
    seen, uniq = set(), []
    for r in rows:
        if r["url"] not in seen:
            seen.add(r["url"]); uniq.append(r)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(uniq[0]))
        w.writeheader(); w.writerows(uniq)
    n1 = sum(r["label"] for r in uniq)
    print(f"Wrote {len(uniq):,} URLs ({n1:,} phishing in {cid:,} campaigns, {len(uniq) - n1:,} safe) -> {path}")
    print("NOTE: synthetic data. Use `python -m phishstream.ingest.real_feeds` for real feeds.")


if __name__ == "__main__":
    generate()
