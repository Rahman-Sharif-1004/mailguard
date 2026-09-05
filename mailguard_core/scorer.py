"""
Risk Scoring & Classification (Section 23 of the report).
Combines the five weighted criteria into a single 0-100 score, maps it
to a category, and applies the automatic escalation rule: an auth
failure combined with a spoofed/IP-based link is escalated to at least
High Risk regardless of the content score.
"""

from .parser import parse_email
from .header_analysis import evaluate_headers
from .url_analysis import evaluate_urls
from .content_analysis import evaluate_content
from .attachment_analysis import evaluate_attachments
from .structural_analysis import evaluate_structure

CATEGORIES = [
    (0, 19, "Safe", "safe"),
    (20, 39, "Low Risk", "low"),
    (40, 59, "Suspicious", "suspicious"),
    (60, 79, "High Risk", "high"),
    (80, 100, "Confirmed Phishing", "phishing"),
]


def _categorize(score: int):
    for lo, hi, label, css_class in CATEGORIES:
        if lo <= score <= hi:
            return label, css_class
    return "Confirmed Phishing", "phishing"


def analyze_email(raw_text: str) -> dict:
    parsed = parse_email(raw_text)

    header_score, header_reasons, auth_failed = evaluate_headers(parsed["headers"])
    url_score, url_reasons, spoofed_or_ip = evaluate_urls(parsed["urls"])
    content_score, content_reasons = evaluate_content(parsed["body"])
    attach_score, attach_reasons = evaluate_attachments(parsed["attachments"])
    struct_score, struct_reasons = evaluate_structure(parsed["body"], len(parsed["urls"]))

    total = header_score + url_score + content_score + attach_score + struct_score
    total = min(total, 100)

    escalated = False
    if auth_failed and spoofed_or_ip and total < 60:
        total = 60
        escalated = True

    category, css_class = _categorize(total)

    all_reasons = header_reasons + url_reasons + content_reasons + attach_reasons + struct_reasons
    if escalated:
        all_reasons.insert(0, "Escalated: sender-authentication failure combined with a spoofed/IP-based link")

    return {
        "score": total,
        "category": category,
        "css_class": css_class,
        "reasons": all_reasons if all_reasons else ["No significant phishing indicators detected"],
        "breakdown": {
            "Sender & Header": {"points": header_score, "max": 25},
            "URL & Link": {"points": url_score, "max": 25},
            "Content (NLP)": {"points": content_score, "max": 25},
            "Attachment": {"points": attach_score, "max": 15},
            "Structural": {"points": struct_score, "max": 10},
        },
        "parsed": parsed,
    }
