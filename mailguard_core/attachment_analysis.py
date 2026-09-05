"""
Attachment Scanning (Section 20 of the report) - weight 15%.
Metadata-level checks only: high-risk file types, double extensions,
and finance-themed filenames. No binary or behavioural analysis is
performed (documented limitation, Section 32).
"""

import re

WEIGHT = 15
HIGH_RISK_EXT = {'.exe', '.scr', '.bat', '.js', '.vbs', '.docm', '.xlsm', '.jar', '.msi'}
FINANCE_WORDS = ['invoice', 'payment', 'receipt', 'refund', 'statement', 'billing']


def evaluate_attachments(attachments: list) -> tuple:
    """Returns (score_out_of_15, list_of_reason_strings)."""
    if not attachments:
        return 0, []

    score = 0
    reasons = []

    for att in attachments:
        filename = att.get("filename", "")
        lower = filename.lower()

        # High-risk extension (worth 8 pts, once)
        if any(lower.endswith(ext) for ext in HIGH_RISK_EXT):
            score += 8
            reasons.append(f"Attachment \"{filename}\" is a high-risk file type")

        # Double extension e.g. invoice.pdf.exe (worth 5 pts, once)
        if re.search(r'\.\w{2,4}\.(exe|scr|bat|js|vbs)$', lower):
            score += 5
            reasons.append(f"Attachment \"{filename}\" uses a double file extension to disguise its real type")

        # Finance-themed filename (worth 2 pts, once)
        if any(word in lower for word in FINANCE_WORDS):
            score += 2
            reasons.append(f"Attachment \"{filename}\" uses a finance-themed name commonly seen in malicious campaigns")

    return min(score, WEIGHT), reasons
