"""
feature_extractor.py
---------------------
Extracts lightweight, purely lexical (URL-string-only) features used by
PhishGuard AI to classify a URL as phishing or legitimate.

Design note
-----------
Every feature here is computed directly from the URL string with no live
network/DNS/WHOIS calls. This keeps prediction latency near-zero and lets
the model run fully offline -- a deliberate, documented deviation from
richer host- and content-based feature sets (e.g. domain age, WHOIS
registration length, page rank) used in some literature, which require
third-party lookups that are slow and can themselves be blocked or rate
limited. See README.md -> "Research Paper Summary" for the justification.
(Domain-age / WHOIS data is still surfaced in the UI -- see
utils/domain_intel.py -- but deliberately kept OUT of the model's feature
vector so predictions stay instant and offline-safe.)

v2 feature set (20 features)
-----------------------------
Original 10 (v1, kept unchanged for backward compatibility):
    1.  url_length
    2.  num_dots
    3.  num_hyphens
    4.  has_ip
    5.  has_https
    6.  suspicious_keyword_count
    7.  num_digits
    8.  num_subdomains
    9.  has_at_symbol
    10. is_shortened

New in v2 -- all O(len(url)) or cheaper, no external calls:
    11. shannon_entropy          -- randomness of the character distribution;
                                     algorithmically-generated phishing
                                     hostnames tend to score higher than
                                     human-chosen domain names.
    12. digit_ratio               -- num_digits / url_length.
    13. special_char_ratio        -- non-alphanumeric chars / url_length.
    14. longest_token_length      -- length of the longest '.', '-', '/', '_',
                                     '?', '=', '&' delimited token.
    15. suspicious_tld            -- 1 if the TLD is one commonly abused for
                                     cheap/disposable phishing domains.
    16. max_char_repeat           -- longest run of one repeated character
                                     (e.g. "111111" or "aaaa").
    17. path_depth                -- number of non-empty '/' segments after
                                     the host.
    18. query_param_count         -- number of query-string parameters.
    19. encoded_char_count        -- number of percent-encoded sequences
                                     (e.g. %20, %3A) -- a common obfuscation
                                     technique.
    20. suspicious_keyword_density -- suspicious_keyword_count / url_length.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, fields
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Keywords commonly stuffed into phishing URLs to build false trust or
# urgency (drawn from patterns discussed across phishing-detection
# literature, e.g. brand/action words appended to unrelated domains).
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "webscr", "ebayisapi", "paypal", "suspend",
    "urgent", "billing", "invoice", "click", "reset", "unlock", "alert",
    "wallet", "gift", "bonus", "free", "recover", "authenticate",
]

# Known URL-shortening services -- shortened links are a common phishing
# obfuscation technique because they hide the true destination domain.
SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy",
]

# TLDs repeatedly flagged as disproportionately abused for phishing in
# public threat reports (cheap/free registration, weak abuse enforcement).
# This is a heuristic signal, not an accusation against any registry.
SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "tk", "gq", "ml", "cf", "ga", "work", "click",
    "link", "country", "kim", "loan", "men", "review", "download", "racing",
    "win", "party", "science", "gdn", "bid", "stream", "icu", "cam",
}

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_TOKEN_SPLIT_RE = re.compile(r"[./\-_?=&]+")
_ENCODED_CHAR_RE = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass
class URLFeatures:
    """Container for a single URL's extracted feature vector."""

    url_length: int
    num_dots: int
    num_hyphens: int
    has_ip: int
    has_https: int
    suspicious_keyword_count: int
    num_digits: int
    num_subdomains: int
    has_at_symbol: int
    is_shortened: int
    shannon_entropy: float
    digit_ratio: float
    special_char_ratio: float
    longest_token_length: int
    suspicious_tld: int
    max_char_repeat: int
    path_depth: int
    query_param_count: int
    encoded_char_count: int
    suspicious_keyword_density: float

    @staticmethod
    def feature_names() -> list[str]:
        """Ordered list of feature column names (used by model + SHAP)."""
        return [f.name for f in fields(URLFeatures)]

    def to_list(self) -> list[float]:
        """Feature vector in the fixed order expected by the model."""
        return [getattr(self, name) for name in self.feature_names()]


def _get_hostname(url: str) -> str:
    """Best-effort hostname extraction, tolerant of missing schemes."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
        return parsed.hostname or ""
    except ValueError:
        return ""


def _get_parsed(url: str):
    """Best-effort full urlparse result, tolerant of missing schemes."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        return urlparse(candidate)
    except ValueError:
        return None


def _has_ip_address(hostname: str) -> int:
    """Return 1 if the hostname is a raw IPv4/IPv6 address."""
    if not hostname:
        return 0
    host = hostname.strip("[]")  # strip IPv6 brackets if present
    if _IPV4_RE.match(host):
        try:
            ipaddress.IPv4Address(host)
            return 1
        except ipaddress.AddressValueError:
            return 0
    try:
        ipaddress.IPv6Address(host)
        return 1
    except ipaddress.AddressValueError:
        return 0


def _count_subdomains(hostname: str) -> int:
    """Number of subdomain labels before the registrable domain+TLD.

    Simple heuristic: split on '.' and treat everything before the last
    two labels (domain + TLD) as subdomains. Good enough for lexical
    scoring without a public-suffix-list dependency.
    """
    if not hostname or _has_ip_address(hostname):
        return 0
    labels = [label for label in hostname.split(".") if label]
    if len(labels) <= 2:
        return 0
    return len(labels) - 2


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string -- higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _longest_token_length(url: str) -> int:
    """Length of the longest token once the URL is split on common delimiters."""
    tokens = [t for t in _TOKEN_SPLIT_RE.split(url) if t]
    return max((len(t) for t in tokens), default=0)


def _max_char_repeat(url: str) -> int:
    """Length of the longest run of one repeated character in the URL."""
    if not url:
        return 0
    longest = current = 1
    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def _suspicious_tld(hostname: str) -> int:
    """Return 1 if the hostname's TLD is on the commonly-abused TLD list."""
    if not hostname or _has_ip_address(hostname):
        return 0
    labels = [label for label in hostname.split(".") if label]
    if not labels:
        return 0
    tld = labels[-1].lower()
    return 1 if tld in SUSPICIOUS_TLDS else 0


def extract_features(url: str) -> URLFeatures:
    """Extract the full lexical feature set for a single URL string.

    Args:
        url: Raw URL string as pasted by the user (scheme optional).

    Returns:
        URLFeatures dataclass instance with every computed feature.
    """
    if not url or not isinstance(url, str):
        raise ValueError("A non-empty URL string is required.")

    clean_url = url.strip()
    hostname = _get_hostname(clean_url)
    lowered = clean_url.lower()
    parsed = _get_parsed(clean_url)

    url_length = len(clean_url)
    num_digits = sum(ch.isdigit() for ch in clean_url)
    suspicious_kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered)
    special_chars = sum(1 for ch in clean_url if not ch.isalnum())

    path = parsed.path if parsed else ""
    query = parsed.query if parsed else ""
    path_depth = len([seg for seg in path.split("/") if seg])
    query_param_count = len([p for p in query.split("&") if p]) if query else 0

    features = URLFeatures(
        url_length=url_length,
        num_dots=clean_url.count("."),
        num_hyphens=clean_url.count("-"),
        has_ip=_has_ip_address(hostname),
        has_https=1 if lowered.startswith("https://") else 0,
        suspicious_keyword_count=suspicious_kw_count,
        num_digits=num_digits,
        num_subdomains=_count_subdomains(hostname),
        has_at_symbol=1 if "@" in clean_url else 0,
        is_shortened=1 if any(svc in lowered for svc in SHORTENING_SERVICES) else 0,
        shannon_entropy=round(_shannon_entropy(clean_url), 4),
        digit_ratio=round(num_digits / url_length, 4) if url_length else 0.0,
        special_char_ratio=round(special_chars / url_length, 4) if url_length else 0.0,
        longest_token_length=_longest_token_length(clean_url),
        suspicious_tld=_suspicious_tld(hostname),
        max_char_repeat=_max_char_repeat(clean_url),
        path_depth=path_depth,
        query_param_count=query_param_count,
        encoded_char_count=len(_ENCODED_CHAR_RE.findall(clean_url)),
        suspicious_keyword_density=round(suspicious_kw_count / url_length, 4) if url_length else 0.0,
    )

    logger.debug("Extracted features for %s: %s", url, features)
    return features


def extract_features_dict(url: str) -> dict:
    """Convenience wrapper returning features as a plain dict."""
    feats = extract_features(url)
    return {name: getattr(feats, name) for name in feats.feature_names()}
