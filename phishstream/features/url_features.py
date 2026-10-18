"""Lexical URL features: computed from the URL string alone, so scoring works in real time
with no page fetch or DNS lookup. Shared by the scikit-learn model, Spark jobs and the API."""
import math
import re
from collections import Counter
from urllib.parse import urlsplit

BRANDS = ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay", "irctc", "amazon", "flipkart",
          "jio", "airtel", "uidai", "aadhaar", "epfo", "incometax", "fastag", "indiapost", "bluedart",
          "mahavitaran", "bescom", "paypal", "microsoft", "netflix", "whatsapp", "instagram", "apple",
          "google", "facebook", "dhl", "fedex", "office", "outlook", "chase", "wellsfargo", "binance"]
LURE_WORDS = ["kyc", "verify", "update", "secure", "login", "signin", "account", "reward", "redeem", "refund",
              "bill", "parcel", "delivery", "blocked", "suspended", "locked", "winner", "gift", "lucky",
              "loan", "otp", "confirm", "bonus", "claim", "wallet", "netbanking", "password", "invoice"]
RISKY_TLDS = {"xyz", "top", "online", "click", "shop", "site", "live", "icu", "buzz", "vip", "info", "cfd",
              "sbs", "rest", "store", "club", "work", "monster", "quest", "tk", "ml", "ga", "cf", "gq"}
FREE_HOSTS = ("web.app", "firebaseapp.com", "weebly.com", "github.io", "netlify.app", "vercel.app",
              "ngrok-free.app", "000webhostapp.com", "blogspot.com", "glitch.me", "pages.dev", "workers.dev")
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy", "t.co", "goo.gl", "ow.ly"}
# official domains of targeted brands (a brand name on these is NOT suspicious)
OFFICIAL = {"onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
            "paytm.com", "phonepe.com", "irctc.co.in", "amazon.in", "amazon.com", "flipkart.com", "jio.com",
            "airtel.in", "uidai.gov.in", "epfindia.gov.in", "incometax.gov.in", "indiapost.gov.in",
            "bluedart.com", "paypal.com", "microsoft.com", "microsoftonline.com", "live.com", "office.com",
            "netflix.com", "whatsapp.com", "instagram.com", "apple.com", "icloud.com", "google.com",
            "facebook.com", "mahadiscom.in", "outlook.com"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
TOKEN_RE = re.compile(r"[a-z]+")

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "n_dots_host", "n_hyphens_host", "n_digits_host",
    "n_digits_url", "n_subdomains", "path_depth", "n_params", "has_https", "has_port", "is_ip_host",
    "has_at", "risky_tld", "free_host", "shortener", "brand_in_host_unofficial", "brand_in_path",
    "n_lure_words", "host_entropy", "url_entropy", "longest_token_host", "digit_ratio_host",
    "has_wp_path", "has_php", "official_domain",
]


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "gov", "ac", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def split(url):
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return u.lower(), "", "", "", None
    return u.lower(), host, p.path or "", p.query or "", port


def brand_of(host_or_url):
    toks = TOKEN_RE.findall(host_or_url.lower())
    for b in sorted(BRANDS, key=len, reverse=True):
        if any(t.startswith(b) or t.endswith(b) for t in toks):
            return b
    return ""


def lure_words(text):
    return [w for w in LURE_WORDS if w in text]


def extract(url: str) -> list[float]:
    u, host, path, query, port = split(url)
    rd = registered_domain(host) if host else ""
    official = rd in OFFICIAL or host in OFFICIAL
    host_toks = TOKEN_RE.findall(host)
    brand_host = brand_of(host)
    return [
        len(u), len(host), len(path), len(query), host.count("."), host.count("-"),
        sum(ch.isdigit() for ch in host), sum(ch.isdigit() for ch in u),
        max(0, host.count(".") - 1), path.count("/"), query.count("&") + (1 if query else 0),
        int(u.startswith("https://")), int(port is not None), int(bool(IP_RE.match(host))),
        int("@" in u), int(host.rsplit(".", 1)[-1] in RISKY_TLDS if "." in host else 0),
        int(host.endswith(FREE_HOSTS)), int(host in SHORTENERS),
        int(bool(brand_host) and not official), int(bool(brand_of(path))),
        len(lure_words(u)), entropy(host), entropy(u),
        max((len(t) for t in host_toks), default=0),
        (sum(ch.isdigit() for ch in host) / len(host)) if host else 0.0,
        int("/wp-" in path), int(".php" in path), int(official),
    ]


def explain(url: str) -> list[str]:
    """Human-readable reasons, used in the API response."""
    f = dict(zip(FEATURE_NAMES, extract(url)))
    _, host, *_ = split(url)
    out = []
    if f["brand_in_host_unofficial"]:
        out.append(f"Uses the name \"{brand_of(host)}\" but is not that brand's official website")
    if f["risky_tld"]:
        out.append(f"Ends in .{host.rsplit('.', 1)[-1]}, a domain ending heavily used for phishing")
    if f["is_ip_host"]:
        out.append("Uses a raw IP address instead of a website name")
    if f["free_host"]:
        out.append("Hosted on a free website builder, which scammers often abuse")
    if f["n_lure_words"]:
        out.append("Contains bait words: " + ", ".join(lure_words(url.lower())[:4]))
    if f["n_hyphens_host"] >= 2:
        out.append("Has many hyphens in the website name")
    if f["brand_in_path"] and not f["official_domain"] and not f["brand_in_host_unofficial"]:
        where = "a WordPress folder" if f["has_wp_path"] else "a folder"
        out.append(f"The name \"{brand_of(split(url)[2])}\" is hidden inside {where} of an unrelated website, typical of hacked sites")
    if f["shortener"]:
        out.append("A short link hides the real destination")
    return out
