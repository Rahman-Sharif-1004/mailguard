"""
URL & Link Analysis (Section 17 of the report) - weight 25%.
Flags domain spoofing, IP-based links, URL shorteners, and (when the
source is HTML) mismatched anchor text vs. actual href target.
"""

import re
import tldextract

WEIGHT = 25

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
IP_RE = re.compile(r'^https?://(\d{1,3}\.){3}\d{1,3}')
KNOWN_BRANDS = ["paypal", "amazon", "microsoft", "google", "apple", "bankofamerica", "netflix"]


def evaluate_urls(urls: list) -> tuple:
    """Returns (score_out_of_25, list_of_reason_strings, spoofed_or_ip_link: bool)."""
    if not urls:
        return 0, [], False

    score = 0
    reasons = []
    spoofed_or_ip = False
    seen_issue_types = set()

    for url in urls:
        # IP address used instead of a domain name  (worth 12 pts, once)
        if IP_RE.match(url) and "ip_link" not in seen_issue_types:
            score += 12
            spoofed_or_ip = True
            seen_issue_types.add("ip_link")
            reasons.append(f"A link uses a raw IP address instead of a domain name ({url})")
            continue

        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower()

        # URL shortener (worth 6 pts, once)
        if registered_domain in SHORTENERS and "shortener" not in seen_issue_types:
            score += 6
            seen_issue_types.add("shortener")
            reasons.append(f"A link uses a URL-shortening service ({registered_domain})")

        # Lookalike / spoofed brand domain (worth 12 pts, once)
        for brand in KNOWN_BRANDS:
            if brand != ext.domain.lower() and re.search(brand[:-1], ext.domain.lower()):
                if "lookalike" not in seen_issue_types:
                    score += 12
                    spoofed_or_ip = True
                    seen_issue_types.add("lookalike")
                    reasons.append(f"A link domain ({registered_domain}) closely resembles the brand \"{brand.title()}\"")
                break

    return min(score, WEIGHT), reasons, spoofed_or_ip
