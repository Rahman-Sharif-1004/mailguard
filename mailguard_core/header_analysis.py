"""
Sender & Header Legitimacy (Section 18 of the report) - weight 25%.
Flags From/Reply-To mismatches, display-name spoofing, and missing or
failed SPF / DKIM / DMARC authentication results.
"""

import re

WEIGHT = 25
KNOWN_BRANDS = ["paypal", "amazon", "microsoft", "google", "apple", "bankofamerica", "netflix"]


def _domain_of(address: str) -> str:
    match = re.search(r'@([\w\.-]+)', address or "")
    return match.group(1).lower() if match else ""


def evaluate_headers(headers: dict) -> tuple:
    """Returns (score_out_of_25, list_of_reason_strings, auth_failed: bool)."""
    score = 0
    reasons = []
    auth_failed = False

    from_addr = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")

    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to)

    # 1) Reply-To domain mismatch  (worth 8 pts)
    if reply_domain and from_domain and reply_domain != from_domain:
        score += 8
        reasons.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")

    # 2) Display-name spoofing: "PayPal Support <random@weird-domain.com>" (worth 8 pts)
    display_name = re.sub(r'<.*?>', '', from_addr).strip().strip('"').lower()
    for brand in KNOWN_BRANDS:
        if brand in display_name and brand not in from_domain:
            score += 8
            reasons.append(f"Display name references \"{brand.title()}\" but the sending domain does not")
            break

    # 3) Lookalike domain check e.g. paypa1-secure.com, secure-paypal-verify.com (worth 5 pts)
    for brand in KNOWN_BRANDS:
        lookalike = re.sub(r'[o0]', '[o0]', brand)
        if from_domain and brand != from_domain.split('.')[0] and re.search(brand[:-1], from_domain):
            score += 5
            reasons.append(f"Sending domain ({from_domain}) closely resembles the brand \"{brand.title()}\"")
            break

    # 4) SPF / DKIM / DMARC authentication results (worth 9 pts)
    auth_header = headers.get("Authentication-Results", "")
    if not auth_header:
        score += 5
        reasons.append("No SPF/DKIM/DMARC authentication result present — sender authenticity could not be verified")
    else:
        auth_lower = auth_header.lower()
        failed = []
        if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
            failed.append("SPF")
        if "dkim=fail" in auth_lower:
            failed.append("DKIM")
        if "dmarc=fail" in auth_lower:
            failed.append("DMARC")
        if failed:
            score += 9
            auth_failed = True
            reasons.append(f"{' and '.join(failed)} authentication failed for the sending domain")

    return min(score, WEIGHT), reasons, auth_failed
