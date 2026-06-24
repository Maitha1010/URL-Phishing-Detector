"""
feature_extractor.py
--------------------
Takes a URL string and returns a dictionary of numeric features.
No live network requests are made — everything is computed from
the URL text alone.

Usage:
    from src.feature_extractor import extract_features
    features = extract_features("http://paypal-login.example.com/verify?user=1")
"""

import re
import math
import urllib.parse
import tldextract


# ---------------------------------------------------------------------------
# Suspicious keywords — presence of these in a URL raises risk
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "bank",
    "confirm", "password", "signin", "ebayisapi", "webscr",
    "paypal", "submit", "free", "lucky", "bonus", "alert",
]

# ---------------------------------------------------------------------------
# TLDs that are disproportionately abused in phishing campaigns
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",   # free Freenom TLDs
    "xyz", "top", "club", "online",
    "site", "website", "space", "icu",
    "buzz", "live", "click",
}


# ---------------------------------------------------------------------------
# Helper: Shannon entropy
# ---------------------------------------------------------------------------
def _shannon_entropy(text: str) -> float:
    """
    Measures how random / unpredictable the characters in a string are.
    A normal English word scores ~3.0; a random hash like 'a8f3k9' scores ~4.5+.
    High entropy in a URL often signals auto-generated or obfuscated domains.
    """
    if not text:
        return 0.0
    length = len(text)
    # Count how often each character appears
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    # Apply the entropy formula
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Helper: is the host a raw IP address?
# ---------------------------------------------------------------------------
def _is_ip_address(host: str) -> bool:
    """
    Returns True if the host looks like 192.168.1.1 (IPv4).
    Legitimate sites almost never use raw IPs in their URLs.
    """
    # Simple IPv4 pattern: four groups of digits separated by dots
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, host))


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------
def extract_features(url: str) -> dict:
    """
    Given a URL string, returns a flat dictionary of numeric features.
    All values are numbers (int or float) so they feed directly into
    a scikit-learn model.

    Parameters
    ----------
    url : str
        The raw URL, e.g. "https://www.example.com/page?id=42"

    Returns
    -------
    dict
        Feature name → numeric value
    """

    # --- Parse the URL into its parts ---
    # Some URLs in real datasets are malformed (e.g. contain [.] in the host).
    # If parsing fails entirely, return a row of zeros rather than crashing.
    try:
        parsed = urllib.parse.urlparse(url)
        # Access .port to trigger any validation error early
        _ = parsed.port
    except Exception:
        return {k: 0 for k in [
            "full_url_length", "host_length", "path_length", "token_count",
            "digit_count", "digit_ratio", "hyphen_count", "dot_count",
            "subdomain_count", "is_ip_address", "suspicious_keyword_count",
            "url_entropy", "uses_https", "has_suspicious_tld", "has_at_symbol",
            "has_explicit_port", "has_repeated_delimiters", "brand_in_subdomain",
            "has_homoglyph_chars",
        ]}

    # tldextract gives us cleaner domain parts:
    #   subdomain="www", domain="example", suffix="com"
    extracted = tldextract.extract(url)

    host   = parsed.netloc or ""          # e.g. "www.example.com:8080"
    path   = parsed.path or ""            # e.g. "/page/item"
    scheme = parsed.scheme.lower()        # e.g. "https"
    tld    = extracted.suffix.lower()     # e.g. "com"

    # Remove the port from the host string for length measurements
    # e.g. "www.example.com:8080" → "www.example.com"
    host_no_port = host.split(":")[0]

    # The full URL lowercased, used for keyword searching
    url_lower = url.lower()

    # -----------------------------------------------------------------------
    # GROUP 1 — LEXICAL FEATURES
    # (things about the characters and words in the URL)
    # -----------------------------------------------------------------------

    full_url_length = len(url)

    host_length = len(host_no_port)

    path_length = len(path)

    # Token count: split on common URL separators and count non-empty pieces
    tokens = re.split(r"[/\-_\.\?=&]", url)
    token_count = len([t for t in tokens if t])

    # Digit count and ratio
    digit_count = sum(1 for ch in url if ch.isdigit())
    digit_ratio = round(digit_count / full_url_length, 4) if full_url_length > 0 else 0.0

    hyphen_count = url.count("-")

    dot_count = url.count(".")

    # Subdomain count: "a.b.example.com" has 2 subdomains (a, b)
    subdomain_parts = extracted.subdomain.split(".") if extracted.subdomain else []
    subdomain_count = len([s for s in subdomain_parts if s])

    is_ip = int(_is_ip_address(host_no_port))   # 1 = IP address, 0 = normal domain

    # Count how many suspicious keywords appear in the URL
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Shannon entropy of the full URL
    url_entropy = _shannon_entropy(url)

    # -----------------------------------------------------------------------
    # GROUP 2 — STRUCTURAL / HOST FEATURES
    # (things about how the URL is constructed)
    # -----------------------------------------------------------------------

    uses_https = int(scheme == "https")   # 1 = HTTPS, 0 = HTTP or other

    # Suspicious TLD flag: 1 if the TLD is on our watch-list
    has_suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    # "@" in a URL tricks the browser — everything before @ is ignored
    # e.g. http://trusted.com@evil.com  →  actually goes to evil.com
    has_at_symbol = int("@" in url)

    # Explicit port number (anything other than the default 80/443)
    port = parsed.port  # None if not present
    has_explicit_port = int(port is not None and port not in (80, 443))

    # -----------------------------------------------------------------------
    # GROUP 3 — DERIVED RISK INDICATORS
    # (combinations and pattern flags)
    # -----------------------------------------------------------------------

    # Repeated delimiters: e.g. "//", "??", "&&" suggest obfuscation
    has_repeated_delimiters = int(bool(re.search(r"[/\-_\.]{2,}", url)))

    # Brand impersonation signal: a known brand name appears in the subdomain
    # (not in the registered domain itself) — classic phishing trick
    KNOWN_BRANDS = ["paypal", "apple", "google", "microsoft", "amazon",
                    "netflix", "ebay", "bank", "facebook", "instagram"]
    brand_in_subdomain = int(
        any(brand in extracted.subdomain.lower() for brand in KNOWN_BRANDS)
        if extracted.subdomain else False
    )

    # Simple homoglyph flag: digits that look like letters (0→o, 1→l, 3→e)
    # e.g. "paypa1" or "g00gle"
    homoglyph_pattern = re.compile(r"(0(?=[a-z])|(?<=[a-z])0|1(?=[a-z])|(?<=[a-z])1|3(?=[a-z])|(?<=[a-z])3)")
    has_homoglyph_chars = int(bool(homoglyph_pattern.search(url_lower)))

    # -----------------------------------------------------------------------
    # Pack everything into a dictionary and return
    # -----------------------------------------------------------------------
    features = {
        # Lexical
        "full_url_length":          full_url_length,
        "host_length":              host_length,
        "path_length":              path_length,
        "token_count":              token_count,
        "digit_count":              digit_count,
        "digit_ratio":              digit_ratio,
        "hyphen_count":             hyphen_count,
        "dot_count":                dot_count,
        "subdomain_count":          subdomain_count,
        "is_ip_address":            is_ip,
        "suspicious_keyword_count": suspicious_keyword_count,
        "url_entropy":              url_entropy,
        # Structural
        "uses_https":               uses_https,
        "has_suspicious_tld":       has_suspicious_tld,
        "has_at_symbol":            has_at_symbol,
        "has_explicit_port":        has_explicit_port,
        # Derived
        "has_repeated_delimiters":  has_repeated_delimiters,
        "brand_in_subdomain":       brand_in_subdomain,
        "has_homoglyph_chars":      has_homoglyph_chars,
    }

    return features


# ---------------------------------------------------------------------------
# Quick demo — runs only when you execute this file directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_urls = [
        # Likely benign
        "https://www.bbc.co.uk/news/technology",
        # Suspicious: long, lots of hyphens, odd TLD
        "http://secure-login-paypal-account.verify.xyz/update?user=123",
        # Suspicious: raw IP address
        "http://192.168.1.104/login/bank-verify",
        # Suspicious: @ trick and keyword
        "http://paypal.com@evil-site.tk/confirm",
    ]

    print(f"{'Feature':<30} ", end="")
    for i in range(len(test_urls)):
        print(f"URL{i+1:>6}  ", end="")
    print()
    print("-" * (30 + 10 * len(test_urls)))

    # Extract features for all URLs
    all_features = [extract_features(u) for u in test_urls]

    # Print each feature as a row
    for feature_name in all_features[0].keys():
        print(f"{feature_name:<30} ", end="")
        for f in all_features:
            print(f"{str(f[feature_name]):>8}  ", end="")
        print()

    print()
    print("URLs tested:")
    for i, u in enumerate(test_urls):
        print(f"  URL{i+1}: {u}")
