import re
import math
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "confirm", "signin", "reset"
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_url_features(url: str) -> dict:
    parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    host = parsed.netloc or ""
    path = parsed.path or ""

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": sum(not c.isalnum() for c in url),
        "entropy": shannon_entropy(url),
        "has_ip": int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", host))),
        "https": int(url.startswith("https")),
        "suspicious_words": sum(k in url.lower() for k in SUSPICIOUS_KEYWORDS),
        "path_length": len(path),
    }
