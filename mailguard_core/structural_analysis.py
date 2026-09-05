"""
Structural Anomalies (Section 15 of the report) - weight 10%.
Detects poor formatting consistency such as excessive capitalisation
and a high ratio of links to visible text.
"""

import re

WEIGHT = 10


def evaluate_structure(body: str, url_count: int) -> tuple:
    """Returns (score_out_of_10, list_of_reason_strings)."""
    if not body.strip():
        return 0, []

    score = 0
    reasons = []

    # Excessive capitalisation (shouting) - worth 5 pts
    letters = re.findall(r'[A-Za-z]', body)
    if letters:
        caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if caps_ratio > 0.3:
            score += 5
            reasons.append("Unusually high ratio of capitalised text (shouting-style formatting)")

    # High ratio of links to visible text - worth 5 pts
    word_count = max(1, len(body.split()))
    if url_count > 0 and (url_count / word_count) > 0.08:
        score += 5
        reasons.append("Unusually high ratio of links to visible text")

    return min(score, WEIGHT), reasons
